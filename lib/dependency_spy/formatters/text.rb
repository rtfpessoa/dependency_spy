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
require 'colorize'
require_relative '../helper/helper'

module DependencySpy
  class Formatters
    class Text

      def self.format(manifests, severity_threshold = nil)
        manifests_text = manifests.map do |manifest|
          manifest_header = "#{manifest.platform}: #{manifest.kind} ~> #{manifest.path} "
          manifest_body = manifest.dependencies.map do |package|
            next unless package.vulnerabilities.any?

            package_header = "    Vulnerable: #{package.name}/#{package.type}:#{package.version}"
            package_body = package.vulnerabilities.map do |vuln|
              first = "        Title: #{vuln.title}\n"
              second = "        Severity: #{(vuln.severity || 'unknown').capitalize}\n"
              third = "        Source: #{vuln.source_url}\n\n"
              if severity_threshold && DependencySpy::Helper.severity_above_threshold?(vuln.severity, severity_threshold)
                "#{first}#{second}#{third}".red
              else
                "#{first}#{second}#{third}"
              end
            end

            "#{package_header}\n#{package_body.join("\n")}"
          end

          next unless manifest_body.any?

          "#{manifest_header}\n#{manifest_body.reject(&:nil?).join("\n")}"
        end

        if manifests_text.any?
          manifests_text.join("\n")
        else
          'No known vulnerabilities were found in your dependencies.'
        end
      end

    end
  end
end
