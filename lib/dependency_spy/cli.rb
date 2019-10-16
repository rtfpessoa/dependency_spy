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
require_relative 'helper/config_file'

module DependencySpy
  class CLI < Thor

    default_task :check
    map '--version' => :version

    FORMATTERS = [
      DependencySpy::Formatters::Text,
      DependencySpy::Formatters::Json,
      DependencySpy::Formatters::Yaml
    ]

    class_option('verbose', :type => :boolean)

    desc('check', 'Check dependencies for known vulnerabilities')
    method_option('config-file-path', :aliases => :c, :type => :string)
    method_option('path', :aliases => :p, :type => :string)
    method_option('files', :type => :string)
    method_option('formatter', :aliases => :f, :type => :string, :enum => FORMATTERS.map { |f| f.name.split('::').last.downcase })
    method_option('platform', :aliases => :m, :type => :string, :enum => YAVDB::Constants::POSSIBLE_PACKAGE_MANAGERS.map(&:downcase))
    method_option('output-path', :aliases => :o, :type => :string)
    method_option('database-path', :type => :string, :aliases => :p)
    method_option('offline', :type => :boolean)
    method_option('severity-threshold', :aliases => :s, :type => :string, :enum => YAVDB::Constants::SEVERITIES)
    method_option('with-color', :type => :boolean)
    method_option('ignore', :aliases => :i, :type => :array)
    def check
      defaults = {
        'verbose' => false,
        'path' => Dir.pwd,
        'formatter' => FORMATTERS.first.name.split('::').last.downcase,
        'database-path' => YAVDB::Constants::DEFAULT_YAVDB_DATABASE_PATH,
        'offline' => false,
        'severity-threshold' => 'low',
        'with-color' => true,
        'ignore' => []
      }
      the_options = defaults.merge(options)

      api_options = the_options.transform_keys(&:to_sym)
      api_options[:database_path] = api_options[:'database-path']
      the_options.freeze; api_options.freeze
      manifests = API.check(api_options)

      formatted_output = if (the_options['formatter'] == 'text') && !the_options['output-path'] && the_options['with-color']
                           DependencySpy::Formatters::Text.format(manifests, the_options['severity-threshold'])
                         else
                           FORMATTERS
                             .find { |f| f.name.split('::').last.downcase == the_options['formatter'] }
                             .format(manifests)
                         end

      if the_options['output-path']
        DependencySpy::Outputs::FileSystem.write(the_options['output-path'], formatted_output)
      else
        DependencySpy::Outputs::StdOut.write(formatted_output)
      end

      has_vulnerabilities =
        manifests.any? do |manifest|
          manifest[:dependencies]&.any? do |dependency|
            dependency[:vulnerabilities]&.any? do |vuln|
              DependencySpy::Helper.severity_above_threshold?(vuln.severity, the_options['severity-threshold'])
            end
          end
        end

      exit(1) if has_vulnerabilities
    end

    method_option('vuln-db-path', :aliases => :d, :type => :string)
    desc('update', 'Download or update database from the official yavdb repository.')

    def update
      defaults = {
        'verbose' => false,
        'vuln-db-path' => YAVDB::Constants::DEFAULT_YAVDB_PATH
      }
      the_options = defaults.merge(options)
      the_options.freeze
      API.update(the_options['vuln-db-path'])
    end

    private

    def options
      cli_options = super
      config_file_options = DependencySpy::ConfigFile.get_config(cli_options[:'config-file-path'])
      config_file_options.merge(cli_options)
    end

  end
end
