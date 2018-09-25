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

  class Manifest < Struct.new(
    :platform, # [String]
    :path, # [String]
    :kind, # [String]
    :dependencies # Array[Dependency]
  )

    def to_map
      map = {}
      members.each do |m|
        next unless self[m] && (
        (self[m].is_a?(String) && !self[m].empty?) ||
          (self[m].is_a?(Array) && self[m].any?))

        map[m.to_s] = self[m] if self[m]
      end
      map
    end

    def to_json(*attrs)
      to_map.to_json(*attrs)
    end

    def to_yaml(*attrs)
      to_map.to_yaml(*attrs)
    end

  end

  class Dependency < Struct.new(
    :name, # [String]
    :version, # [String]
    :type, # [String]
    :vulnerabilities # Array[Advisory]
  )

    def to_map
      map = {}
      members.each do |m|
        next unless self[m] && (
        (self[m].is_a?(String) && !self[m].empty?) ||
          (self[m].is_a?(Array) && self[m].any?))

        map[m.to_s] = self[m] if self[m]
      end
      map
    end

    def to_json(*args)
      to_map.to_json(*args)
    end

    def to_yaml(*args)
      to_map.to_yaml(*args)
    end

  end

end
