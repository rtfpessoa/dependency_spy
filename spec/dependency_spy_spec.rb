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

require 'spec_helper'

RSpec.describe DependencySpy::API do
  describe 'check' do
    detected_manifests = DependencySpy::API.check('examples')

    it 'can read all manifests inside examples' do
      expect(detected_manifests).to have(5).items
    end

    it 'can read all dependencies for npm manifest' do
      manifests    = detected_manifests.select { |m| m.platform == 'npm' }
      dependencies = manifests.map(&:dependencies).flatten
      expect(dependencies).to have(941).items
    end

    it 'can find all vulnerabilities for npm dependencies' do
      manifests       = detected_manifests.select { |m| m.platform == 'npm' }
      dependencies    = manifests.map(&:dependencies).flatten
      vulnerabilities = dependencies.map(&:vulnerabilities).flatten
      expect(vulnerabilities).to have(118).items
    end

    it 'can read all dependencies for rubygems manifest' do
      manifests    = detected_manifests.select { |m| m.platform == 'rubygems' }
      dependencies = manifests.map(&:dependencies).flatten
      expect(dependencies).to have(29).items
    end

    it 'can read all vulnerabilities for rubygems dependencies' do
      manifests       = detected_manifests.select { |m| m.platform == 'rubygems' }
      dependencies    = manifests.map(&:dependencies).flatten
      vulnerabilities = dependencies.map(&:vulnerabilities).flatten
      expect(vulnerabilities).to have(3).items
    end
  end
end
