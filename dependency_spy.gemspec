lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

require 'dependency_spy/version'

Gem::Specification.new do |spec|
  spec.name          = 'dependency_spy'
  spec.version       = DependencySpy::VERSION
  spec.authors       = ['Rodrigo Fernandes']
  spec.email         = ['rodrigo.fernandes@tecnico.ulisboa.pt']
  spec.summary       = 'Finds known vulnerabilities in your dependencies'
  spec.description   = '
    Finds known vulnerabilities in your dependencies
    Using rubysec/ruby-advisory-db, snyk.io, ossindex.net, nodesecurity.io
  '
  spec.homepage      = 'https://github.com/rtfpessoa/dependency_spy'
  spec.license       = 'AGPL-3.0+'
  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features|database)/}) }
  spec.bindir        = 'bin'
  spec.executables   = ['dependency_spy', 'depspy']
  spec.require_paths = ['lib']

  spec.required_ruby_version = '>= 2.3.7'

  # Development
  spec.add_development_dependency 'bundler', ['~> 1.16']
  spec.add_development_dependency 'codacy-coverage'
  spec.add_development_dependency 'rake', ['~> 12.3']
  spec.add_development_dependency 'rspec', ['~> 3.8']
  spec.add_development_dependency 'rspec-collection_matchers', ['~> 1.1']
  spec.add_development_dependency 'simplecov'

  # Linters
  spec.add_development_dependency 'rubocop', ['~> 0.58']
  spec.add_development_dependency 'rubocop-rspec', ['~> 1.27']

  # Runtime
  spec.add_runtime_dependency 'bibliothecary', ['~> 6.3']
  spec.add_runtime_dependency 'thor', ['~> 0.20']
  spec.add_runtime_dependency 'yavdb', ['0.1.0.pre.alpha.2']
  spec.add_runtime_dependency 'semantic_range', ['~> 2.0']
end
