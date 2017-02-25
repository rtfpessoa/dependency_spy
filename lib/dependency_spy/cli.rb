# dependency_spy - Finds known vulnerabilities in your dependencies
# Copyright (C) 2017-2018 Rodrigo Fernandes
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

require 'thor'
require 'yavdb/constants'

require_relative '../dependency_spy'
require_relative 'formatters/text'
require_relative 'formatters/json'
require_relative 'formatters/yaml'
require_relative 'outputs/stdout'
require_relative 'outputs/file'

module DependencySpy
  class CLI < Thor

    default_task :check
    map '--version' => :version

    FORMATTERS = [
      DependencySpy::Formatters::Text,
      DependencySpy::Formatters::Json,
      DependencySpy::Formatters::Yaml
    ]

    class_option('verbose', :type => :boolean, :default => false)

    desc('check', 'Check dependencies for known vulnerabilities')
    method_option('path', :aliases => :p, :type => :string, :default => Dir.pwd)
    method_option('formatter', :aliases => :f, :type => :string, :enum => FORMATTERS.map { |f| f.name.split('::').last.downcase }, :default => FORMATTERS.first.name.split('::').last.downcase)
    method_option('platform', :aliases => :m, :type => :string, :enum => YAVDB::Constants::POSSIBLE_PACKAGE_MANAGERS.map(&:downcase))
    method_option('output-path', :aliases => :o, :type => :string)
    method_option('database-path', :type => :string, :aliases => :p, :default => YAVDB::Constants::DEFAULT_YAVDB_DATABASE_PATH)

    def check
      manifests = API.check(options['path'], options['platform'], options['database-path'])

      formatted_output =
        FORMATTERS
          .find { |f| f.name.split('::').last.downcase == options['formatter'] }
          .format(manifests)

      if options['output-path']
        DependencySpy::Outputs::FileSystem.write(options['output-path'], formatted_output)
      else
        DependencySpy::Outputs::StdOut.write(formatted_output)
      end
    end

    method_option('vuln-db-path', :aliases => :d, :type => :string, :default => YAVDB::Constants::DEFAULT_YAVDB_PATH)
    desc('update', 'Download or update database from the official yavdb repository.')

    def update
      API.update(options['vuln-db-path'])
    end

  end
end
