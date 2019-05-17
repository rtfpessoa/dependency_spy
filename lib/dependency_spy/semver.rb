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

require 'semantic_range'

module DependencySpy

  class SemVer

    def self.intersects(vor1, vor2)
      vor1 = parse(vor1) if vor1.is_a?(String)
      vor2 = parse(vor2) if vor2.is_a?(String)

      if vor1.is_a?(SemanticRange::Range) && vor2.is_a?(SemanticRange::Range)
        vor1.intersects(vor2)
      elsif vor1.is_a?(SemanticRange::Range) && vor2.is_a?(SemanticRange::Version)
        SemanticRange.satisfies(vor2, vor1)
      elsif vor1.is_a?(SemanticRange::Version) && vor2.is_a?(SemanticRange::Range)
        SemanticRange.satisfies(vor1, vor2)
      elsif vor1.is_a?(SemanticRange::Version) && vor2.is_a?(SemanticRange::Version)
        SemanticRange.eq(vor1, vor2)
      else
        vor1 == vor2
      end
    end

    class << self

      private

      def parse(version_or_range, loose = false)
        version_or_range = '>= 0.0.0' if version_or_range == '*'
        return version_or_range if version_or_range.is_a?(SemanticRange::Range) ||
                                   version_or_range.is_a?(SemanticRange::Version)

        begin
          SemanticRange::Version.new(version_or_range, loose)
        rescue SemanticRange::InvalidVersion
          begin
            SemanticRange::Range.new(version_or_range, loose)
          rescue SemanticRange::InvalidRange
            version_or_range
          end
        end
      end

    end

  end

  class ImpossibleComparison < StandardError

    def initialize(msg)
      @msg = msg
    end

  end

end
