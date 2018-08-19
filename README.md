# dependency_spy

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/5ae8d9aa788e4855965974f480a0b91b)](https://www.codacy.com/app/rtfpessoa/dependency_spy?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=rtfpessoa/dependency_spy&amp;utm_campaign=Badge_Grade)
[![Codacy Badge](https://api.codacy.com/project/badge/Coverage/5ae8d9aa788e4855965974f480a0b91b)](https://www.codacy.com/app/rtfpessoa/dependency_spy?utm_source=github.com&utm_medium=referral&utm_content=rtfpessoa/dependency_spy&utm_campaign=Badge_Coverage)
[![CircleCI](https://circleci.com/gh/rtfpessoa/dependency_spy.svg?style=svg)](https://circleci.com/gh/rtfpessoa/dependency_spy)

Finds known vulnerabilities in your dependencies

Thanks to the amazing work done by [libraries.io](https://libraries.io/) all the dependency manifest parsing is
handled by [bibliothecary](https://github.com/librariesio/bibliothecary) and this means we have support for more than 20
package managers. Due to the limited sources of information we only have identified vulnerabilities for the ones listed below.

## Disclaimer

This projects aims to provide an OSS alternative to identify known vulnerabilities for your dependencies.
Although it makes a good effort in doing this, there is no assurance it is finding all the publicly available vulnerabilities.
The maintainers take no responsibility for any harm caused by you relying on it.
Use as a complement to other tools at your own risk.  

## Supported Package Managers

* NPM
* RubyGems
* Maven
* Nuget
* Packagist
* Pypi
* Go

## Prerequisites

* Ruby 2.3 or newer

## Installation

```sh
gem install dependency_spy --pre
```

> Notice the `--pre` in the end

## Usage

### Examples

**Check current directory project**
```
depspy
```

## TODO:

#### Tests

- [ ] Version Comparison

#### Features/Improvements

- [ ] Improve output formatters
- [ ] Add more output options

### Help

    Commands:
      depspy check           # Check dependencies for known vulnerabilities
      depspy help [COMMAND]  # Describe available commands or one specific command
      depspy update          # Update known vulnerabilities database
    
    Options:
      [--verbose], [--no-verbose]   
      d, [--vuln-db-path=VULN-DB-PATH]  # Default: <HOME>/.yavdb/yavdb


## Development

After checking out the repo, run `bin/setup` to install dependencies.
Then, run `bundle exec rake spec` to run the tests.
You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`.
To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`,
which will create a git tag for the version,
push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/rtfpessoa/dependency_spy.
This project is intended to be a safe, welcoming space for collaboration,
and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## Copyright

Copyright (c) 2017-present Rodrigo Fernandes.
See [LICENSE](https://github.com/rtfpessoa/dependency_spy/blob/master/LICENSE.md) for details.
