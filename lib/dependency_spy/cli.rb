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
require_relative 'helper/helper'

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
    method_option('files', :type => :string)
    method_option('formatter', :aliases => :f, :type => :string, :enum => FORMATTERS.map { |f| f.name.split('::').last.downcase }, :default => FORMATTERS.first.name.split('::').last.downcase)
    method_option('platform', :aliases => :m, :type => :string, :enum => YAVDB::Constants::POSSIBLE_PACKAGE_MANAGERS.map(&:downcase))
    method_option('output-path', :aliases => :o, :type => :string)
    method_option('database-path', :type => :string, :aliases => :p, :default => YAVDB::Constants::DEFAULT_YAVDB_DATABASE_PATH)
    method_option('offline', :type => :boolean, :default => false)
    method_option('severity-threshold', :aliases => :s, :type => :string, :enum => YAVDB::Constants::SEVERITIES, :default => 'low')
    method_option('with-color', :type => :boolean, :default => true)
    method_option('ignore', :aliases => :i, :type => :array, :default => [])
    def check
      manifests = API.check(options)

      formatted_output = if (options['formatter'] == 'text') && !options['output-path'] && options['with-color']
                           DependencySpy::Formatters::Text.format(manifests, options['severity-threshold'])
                         else
                           FORMATTERS
                             .find { |f| f.name.split('::').last.downcase == options['formatter'] }
                             .format(manifests)
                         end

      if options['output-path']
        DependencySpy::Outputs::FileSystem.write(options['output-path'], formatted_output)
      else
        DependencySpy::Outputs::StdOut.write(formatted_output)
      end

      has_vulnerabilities =
        manifests.any? do |manifest|
          manifest[:dependencies]&.any? do |dependency|
            dependency[:vulnerabilities]&.any? do |vuln|
              DependencySpy::Helper.severity_above_threshold?(vuln.severity, options['severity-threshold'])
            end
          end
        end

      exit(1) if has_vulnerabilities
    end

    method_option('vuln-db-path', :aliases => :d, :type => :string, :default => YAVDB::Constants::DEFAULT_YAVDB_PATH)
    desc('update', 'Download or update database from the official yavdb repository.')

    def update
      API.update(options['vuln-db-path'])
    end

  end
end
