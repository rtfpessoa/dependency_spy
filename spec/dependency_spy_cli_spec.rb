
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

RSpec::Matchers.define :superset_of do |desired|
  match { |actual| desired.map{|k,v| actual[k] === v}.all? }
end

RSpec.describe DependencySpy::CLI do
  describe 'check' do
    it 'should call API with defaults given no config file' do
      api_call_defaults = {
        :verbose => false,
        :path => Dir.pwd,
        :formatter => 'text',
        :database_path => YAVDB::Constants::DEFAULT_YAVDB_DATABASE_PATH,
        :offline => false,
        :ignore => []
      }
      expect(DependencySpy::API).to receive(:check).with(superset_of(api_call_defaults)).and_return([])
      DependencySpy::CLI.new.check
    end

    it 'should call API with overridden given a config file' do
      api_call_args = {
        :formatter => 'json'
      }
      expect(DependencySpy::ConfigFile).to receive(:get_config).and_return({'formatter' => 'json'})
      expect(DependencySpy::API).to receive(:check).with(superset_of(api_call_args)).and_return([])
      DependencySpy::CLI.new.check
    end

    it 'should call API with overridden given a config file and command line override' do
      api_call_args = {
        :formatter => 'json',
        :offline => false
      }
      # allow(Thor).to receive(:options){{ 'offline' => false }}
      cli = DependencySpy::CLI.new([], 'offline' => false)
      expect(DependencySpy::ConfigFile).to receive(:get_config).and_return({'formatter' => 'json', 'offline' => true})
      expect(DependencySpy::API).to receive(:check).with(superset_of(api_call_args)).and_return([])
      cli.check
    end
  end
end