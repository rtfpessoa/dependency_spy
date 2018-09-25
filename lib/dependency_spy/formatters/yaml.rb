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

module DependencySpy
  class Formatters
    class Yaml

      def self.format(manifests)
        filtered_manifests = manifests.map do |manifest|
          manifest[:dependencies] = manifest[:dependencies].map do |dependency|
            next unless dependency[:vulnerabilities].any?

            dependency[:vulnerabilities] = dependency[:vulnerabilities].map(&:to_map)
            dependency
          end.reject(&:nil?).map(&:to_map)
          manifest
        end

        filtered_manifests
          .reject { |m| m[:dependencies].nil? }
          .map(&:to_map)
          .map(&:to_yaml)
      end

    end
  end
end
