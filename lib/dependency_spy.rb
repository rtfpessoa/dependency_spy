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

require 'net/http'
require 'socket'
require 'yaml'
require 'bibliothecary'
require 'semantic_range'
require 'yavdb'
require 'yavdb/constants'

require_relative 'dependency_spy/dtos/dependency'
require_relative 'dependency_spy/semver'

module DependencySpy
  class API

    def self.check(options)
      path = options[:path] || Dir.pwd
      files = options[:file]
      platform = options[:platform]
      database_path = options[:database_path] || YAVDB::Constants::DEFAULT_YAVDB_DATABASE_PATH
      offline = options[:offline] || false
      ignore = options[:ignore] || []

      if !File.exist?(database_path) && offline
        puts 'No local database found. Cannot obtain database since offline mode is enabled.'
        exit(10)
      elsif !offline
        puts 'Going to update the local vulnerability database.'
        YAVDB::API.download_database(false, YAVDB::Constants::DEFAULT_YAVDB_PATH)
      end

      path             = File.expand_path(path)
      package_managers = find_platform(platform)
      file_list        = if !files.nil?
                           files.split(',')
                         elsif File.file?(path)
                           path = File.dirname(path)
                           [File.basename(path)]
                         else
                           cmd = `find #{path} -type f | grep -vE "#{Bibliothecary.ignored_files_regex}"`
                           cmd.split("\n").sort
                         end
      manifests        = package_managers.map { |pm| pm.analyse(path, file_list) }.flatten.compact
      manifests.map do |manifest|
        package_manager   = manifest[:platform]
        manifest_filename = manifest[:path]
        manifest_kind     = manifest[:kind]

        dependency_vulns = manifest[:dependencies].map do |dependency|
          package_name = dependency[:name] || dependency['name']
          version      = dependency[:requirement] || dependency['version']
          type         = dependency[:type] || dependency['type']

          package_vulns = vulns(manifest[:platform], package_name, database_path)

          vulnerabilities = package_vulns.select do |vuln|
            vulnerable = vuln.vulnerable_versions ? vuln.vulnerable_versions.any? { |vv| DependencySpy::SemVer.intersects(vv, version) } : false
            unaffected = vuln.unaffected_versions ? vuln.unaffected_versions.any? { |vu| DependencySpy::SemVer.intersects(vu, version) } : false
            patched    = vuln.patched_versions ? vuln.patched_versions.any? { |vp| DependencySpy::SemVer.intersects(vp, version) } : false
            ignored    = ignore.include?(vuln.id)

            if unaffected || patched || ignored
              false
            else
              vulnerable
            end
          end

          Dependency.new(package_name, version, type, vulnerabilities.uniq)
        end

        Manifest.new(package_manager, manifest_filename, manifest_kind, dependency_vulns.uniq)
      end
    end

    def self.update(vuln_repo_path = YAVDB::Constants::DEFAULT_YAVDB_PATH)
      YAVDB::API.download_database(true, vuln_repo_path)
    end

    class << self

      private

      def vulns(package_manager, package_name, vuln_database_path)
        YAVDB::API.list_vulnerabilities(package_manager, package_name, vuln_database_path)
      end

      def find_platform(platform)
        if platform.nil?
          Bibliothecary.package_managers
        else
          Bibliothecary::Parsers.constants
            .select { |c| c.to_s.downcase.include?(platform) }
            .map { |c| Bibliothecary::Parsers.const_get(c) }
            .sort_by { |c| c.to_s.downcase }
        end
      end

    end

  end
end
