# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [1.2.8] - 2021-01-10

### Changed

- Updated GeoLite database

### Fixed

- Minor fixes to go mod files

## [1.2.7] - 2019-11-24

### Changed

- Updated GeoLite database
- Removed Mac version

### Fixed

- Minor fixes to bugs introduced by dependency package code changes

## [1.2.6] - 2019-06-27

### Added

- Added whois lookups for creation and modification dates 

### Changed

- Updated GeoLite database
- Improved output text formatting

## [1.2.5] - 2019-05-04

### Added

- Ability to upgrade dnsmorph with -u option

### Changed

- Updated GeoLite database
- Miscellaneous code fixes

## [1.2.4] - 2018-12-29

### Added

- New version check
- Additional homoglyphs

### Changed

- Updated README
- Updated GeoLite database
- Output text formatting

### Fixed

- Broken unicode character printing

## [1.2.3] - 2018-10-20

### Added

- Geolite database unzip at runtime

### Changed

- Updated GeoLite database
- Output text formatting
- Updated goreleaser.yml

## [1.2.2] - 2018-04-20

### Fixed

- Synced versioning

## [1.2.1] - 2018-04-20

### Fixed

- Incorrect release packaging in previous version

## [1.2.0] - 2018-04-20

### Added

- Domain geolocation
- Output to csv
- Output to json
- Option to submit a domains list file for bulk lookups

### Fixed

- Output formatting

### Changed

- Updated demo gif
- Updated documentation

## [1.1.3] - 2018-04-02

### Fixed

- Versioning
- Minor fixes to output coloring

## [1.1.2] - 2018-03-31

### Fixed

- Bug introduced in v.1.1 that made tld's disappear in terminal output

## [1.1.1] - 2018-03-31

### Added

- Arm and arm64 architectures

### Fixed

- Added zip binary distributions for windows releases
- Readme

## [1.1.0] - 2018-03-30

### Added

- Concurrent A record dns lookup

### Fixed

- Domain input validation
- Versioning

### Changed

- Demo gif
- Updated test suite

## [1.0.2] - 2018-03-20

### Added

- Changelog
- License
- Readme
- Contributing guide
- Homograph attack
- Bitsquat attack
- Hyphenation attack
- Omission attack
- Repetition attack
- Replacement attack
- Subdomain attack
- Transposition attack
- Vowel swap attack
- Addition attack
- Travis continuous integration
- Testing suite
- Code coverage report
- Goreleaser release automation
