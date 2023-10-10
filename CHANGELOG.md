# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [7.2.0](https://github.com/stevengoossensB/pyattck/compare/v7.1.2...7.2.0) (2023-10-10)


### Features

* Added a layout module that controls the layout of individual attack types within the console ([8347482](https://github.com/stevengoossensB/pyattck/commit/8347482bd112330e5525de84ab3b36a0a4ce8a2e))
* Added a menu class to handle control flow of our menu system ([2d1bcba](https://github.com/stevengoossensB/pyattck/commit/2d1bcbaade9ed9fc6cb617603027204c64959b2d))
* Added interactive boolean parameter to launch our new interactive console system ([a6528cd](https://github.com/stevengoossensB/pyattck/commit/a6528cd69a5f45502053eae546b789b6307582c2))
* Added interactive class to drive generation and creation of our menu system ([16cf002](https://github.com/stevengoossensB/pyattck/commit/16cf002711f486c2052696e5d19acea46bf7e9bd))
* Added logging and utils to project ([24d34c3](https://github.com/stevengoossensB/pyattck/commit/24d34c38949c4075186b6dd8a9ca4503e0e528d6))
* Added logging support ([6fb0101](https://github.com/stevengoossensB/pyattck/commit/6fb010198493def5b78a156036c731ff6f91b711))
* Added new exports in init ([034f631](https://github.com/stevengoossensB/pyattck/commit/034f631738d27dc87f1e03eed772c6fdea5d986a))
* Added new static variables to base class ([9c08561](https://github.com/stevengoossensB/pyattck/commit/9c08561c9268788dd57e023f9275fed8f99b2411))
* Adding campaigns attribute to Enterprise attack and related entities ([ecf5eba](https://github.com/stevengoossensB/pyattck/commit/ecf5ebad4bd3f6e5639dc796051a582ef7aa7381))
* Adding docs requirement file ([230b15b](https://github.com/stevengoossensB/pyattck/commit/230b15b50ca1e75ff4033cddc27bacc2d353edc9))
* Adding new URL for nist_controls_json ([5d96b89](https://github.com/stevengoossensB/pyattck/commit/5d96b8917859c5086a36a88b3780c386a6e1a55f))
* Adding poetry support for project ([9b495e2](https://github.com/stevengoossensB/pyattck/commit/9b495e24f61153e43b3b8cbb38b4b6e7be186142))
* Bump minor version ([48349f5](https://github.com/stevengoossensB/pyattck/commit/48349f562df95ce28f48918987c2afb8ecc966e7))
* Bumped major version ([b8f2fc2](https://github.com/stevengoossensB/pyattck/commit/b8f2fc2c11f867b5cafd88506545581163f29ff2))
* Bumped patch version ([725d181](https://github.com/stevengoossensB/pyattck/commit/725d1812743c9e66d30bba349cf0a61681d4bcac))
* **configuration:** Added internal method to save_config ([12ccdeb](https://github.com/stevengoossensB/pyattck/commit/12ccdeb19b826b3a77aa6341873b2793f77cb617))
* Simplified main interface to use new simple classes ([cc0eda6](https://github.com/stevengoossensB/pyattck/commit/cc0eda659051fdad5aad6768d230f6bc2a8ee3dc))
* Updated format of properties within each framework ([60e211d](https://github.com/stevengoossensB/pyattck/commit/60e211da499f032e12c18b00a9a3a37b2f96d5a1))
* Updated requirements to use data models and attrs ([bac03ad](https://github.com/stevengoossensB/pyattck/commit/bac03ad4bee7ae36392491fd0169edf20e8f2982))


### Bug Fixes

* Added relationship property to the enterprise framework. Fixes [#131](https://github.com/stevengoossensB/pyattck/issues/131) ([09c8c02](https://github.com/stevengoossensB/pyattck/commit/09c8c02916540fc2d02e8e032214a9b5c1615bab))
* Adding safeload of yaml file to config ([1d08992](https://github.com/stevengoossensB/pyattck/commit/1d089925c39fbaa901779e2d1dc0167dcf064ec8))
* Adding tests for campaigns ([40809bc](https://github.com/stevengoossensB/pyattck/commit/40809bca9985a44101c558ef84ba4f926909a02c))
* Adding warning of deprecation of PreAttack framework since it is no longer officially supported by MITRE. Fixes [#126](https://github.com/stevengoossensB/pyattck/issues/126) ([085828e](https://github.com/stevengoossensB/pyattck/commit/085828e1ffd1a9ebc1f81b1c7cd26b1c145fc4af))
* Bumped major version and update dependencies ([41c5201](https://github.com/stevengoossensB/pyattck/commit/41c5201a6f0046604d5bd0e7d52dfdba7af0d0a5))
* Bumping minor version ([2d89017](https://github.com/stevengoossensB/pyattck/commit/2d8901717e7edc26d6aecef7789b9ade1973e661))
* bumping version to 6.1.2 ([3937632](https://github.com/stevengoossensB/pyattck/commit/393763266c300981776db62e28e538deb8b934ec))
* **configuration:** Updated config to save config when use_config is used. Also fixed issue with is_url method Closes [#121](https://github.com/stevengoossensB/pyattck/issues/121) ([9933bba](https://github.com/stevengoossensB/pyattck/commit/9933bba628947ec340684c6585c2b51f4a97b062))
* **configuration:** Updated validation of URLs and Paths in Configuration class ([c73a7d3](https://github.com/stevengoossensB/pyattck/commit/c73a7d3b7dc034a36b6505119480cc70c942378a))
* Ignoring long line length in base class for logo string ([db21818](https://github.com/stevengoossensB/pyattck/commit/db218184791c23b84e62752e8f9981357667286f))
* Incorporating fix [#129](https://github.com/stevengoossensB/pyattck/issues/129) ([59ed9db](https://github.com/stevengoossensB/pyattck/commit/59ed9dba5fd72ab64e4b3b7ed85d8dcbbb1b0586))
* **layout:** Updated get_external_id method to use a different name than object as its parameter ([30ae9b9](https://github.com/stevengoossensB/pyattck/commit/30ae9b941d89d3b5f0d443d4ebf2469b331ee9b6))
* Removed the __main__ and replaced with cli module ([729707e](https://github.com/stevengoossensB/pyattck/commit/729707e3083e2e5b85fec6bafc01b6499e9db172))
* Update patch version ([b4a5837](https://github.com/stevengoossensB/pyattck/commit/b4a58378b9f8bda08e17fb649e763aca453a235e))
* Updated format of configuration module ([b0d2a09](https://github.com/stevengoossensB/pyattck/commit/b0d2a094e007b4e98a6be310c451901cbbc3e814))
* Updated format to match isort and black ([3e834c1](https://github.com/stevengoossensB/pyattck/commit/3e834c12b2099b553f5d0d98d63cde04601d897f))
* Updated imports of data models ([3c19df1](https://github.com/stevengoossensB/pyattck/commit/3c19df1d73f6424611922ecc50b47e32de61f5dd))
* Updated readme ([48528e1](https://github.com/stevengoossensB/pyattck/commit/48528e18f3a37a9d863586bd779bcfe906b158d7))
* Updating campaigns tests ([58a2c3d](https://github.com/stevengoossensB/pyattck/commit/58a2c3da2863a6628c6490f75a4cd31861adbb1a))
* Updating dependencies ([2a446e6](https://github.com/stevengoossensB/pyattck/commit/2a446e63bc1cc962b67048e2cf91f4c79b14f139))
* Updating dependency in poetry.lock ([ffb5a31](https://github.com/stevengoossensB/pyattck/commit/ffb5a310f0a1369ea796528cabd14023247e12ed))
* Updating imports in frameworks ([d9a2c1d](https://github.com/stevengoossensB/pyattck/commit/d9a2c1dd95ce87a48e3489dbc12223e54a05e627))
* Updating imports of pyattck-data again ([8de8739](https://github.com/stevengoossensB/pyattck/commit/8de8739a16824791f2cd5ecc446997e2ecda3a00))
* Updating test.py examples ([cbfd1f3](https://github.com/stevengoossensB/pyattck/commit/cbfd1f33d586dfcd9a15b3cbbc38daa39e20ccd1))
* Updating to pyattck-data 2.1.1 ([734da49](https://github.com/stevengoossensB/pyattck/commit/734da49add9d5791dba48e6c749d194e163e8168))
* Updating to pyattck-data 2.4.1 ([78a3576](https://github.com/stevengoossensB/pyattck/commit/78a357614ac624aa7a9458b560b9936ecbc8ec3a))
* Updating to pyattck-data 2.4.2 ([71b69a9](https://github.com/stevengoossensB/pyattck/commit/71b69a97324037b2b2dc36d9d42572fa655abb71))
* Updating to pyattck-data latest version ([e3bdea4](https://github.com/stevengoossensB/pyattck/commit/e3bdea4d251d56bb72a5cf0c523e9c4e77694ca6))
* Updating toml ([d3f57c6](https://github.com/stevengoossensB/pyattck/commit/d3f57c6ae3cdb96a823ae5456960f31129ee7d94))
* **utils:** Modified logic in is_path method ([57efb98](https://github.com/stevengoossensB/pyattck/commit/57efb98caa9f7a354b44a8c30f533024770b0ba5))


### Documentation

* Added gif of new interactive menu system ([5d138a3](https://github.com/stevengoossensB/pyattck/commit/5d138a331414c49308aedb103bef2db191729961))
* More updates to docstrings ([3889d80](https://github.com/stevengoossensB/pyattck/commit/3889d803b4856e12ecb9bc0a6e9c06ca208fd05c))
* Revamped documentation based on changes to project ([267e047](https://github.com/stevengoossensB/pyattck/commit/267e0473d65fc756e166140e1a338820736dd6c8))
* Update index.md with interactive console ([f9b3a94](https://github.com/stevengoossensB/pyattck/commit/f9b3a9449bb5e3e15a2e505e703794c36a8bd6eb))
* Updated changelog ([b8c98b9](https://github.com/stevengoossensB/pyattck/commit/b8c98b9d485dec38cb28075dfa3104098e9d29a7))
* updated doc strings in attck and configuration classes ([f367e45](https://github.com/stevengoossensB/pyattck/commit/f367e45e6ec3a6e1697d224f08c5c3e0b47a4195))
* Updated README ([a5f1a4d](https://github.com/stevengoossensB/pyattck/commit/a5f1a4d0749e2e476c8a00f17a7cd54c7b22e5b2))
* Updated README ([4727349](https://github.com/stevengoossensB/pyattck/commit/472734976c02b3fb2a1dcb36f6e4d969645fc679))
* Updating docs ([e0e60a4](https://github.com/stevengoossensB/pyattck/commit/e0e60a48f033b6194a088c555c4c36d32399fbd9))
* Updating docs ([0fceda2](https://github.com/stevengoossensB/pyattck/commit/0fceda228918cbf5d69b86b18ebc1ebbc35d472f))
* Updating docstring formatting in properies ([7b3b2e2](https://github.com/stevengoossensB/pyattck/commit/7b3b2e236a6c6a19561ecff67a5e70fc033684bc))

## [7.1.2](https://github.com/swimlane/pyattck/compare/7.1.1...7.1.2) (2023-05-16)


### Bug Fixes

* Updating test.py examples ([cbfd1f3](https://github.com/swimlane/pyattck/commit/cbfd1f33d586dfcd9a15b3cbbc38daa39e20ccd1))

## [7.1.1](https://github.com/swimlane/pyattck/compare/7.1.0...7.1.1) (2023-03-06)


### Bug Fixes

* Added relationship property to the enterprise framework. Fixes [#131](https://github.com/swimlane/pyattck/issues/131) ([09c8c02](https://github.com/swimlane/pyattck/commit/09c8c02916540fc2d02e8e032214a9b5c1615bab))

## [7.1.0](https://github.com/swimlane/pyattck/compare/7.0.0...7.1.0) (2023-03-06)


### Features

* Adding campaigns attribute to Enterprise attack and related entities ([ecf5eba](https://github.com/swimlane/pyattck/commit/ecf5ebad4bd3f6e5639dc796051a582ef7aa7381))


### Bug Fixes

* Adding tests for campaigns ([40809bc](https://github.com/swimlane/pyattck/commit/40809bca9985a44101c558ef84ba4f926909a02c))
* Adding warning of deprecation of PreAttack framework since it is no longer officially supported by MITRE. Fixes [#126](https://github.com/swimlane/pyattck/issues/126) ([085828e](https://github.com/swimlane/pyattck/commit/085828e1ffd1a9ebc1f81b1c7cd26b1c145fc4af))
* Bumping minor version ([2d89017](https://github.com/swimlane/pyattck/commit/2d8901717e7edc26d6aecef7789b9ade1973e661))
* Incorporating fix [#129](https://github.com/swimlane/pyattck/issues/129) ([59ed9db](https://github.com/swimlane/pyattck/commit/59ed9dba5fd72ab64e4b3b7ed85d8dcbbb1b0586))
* Updated readme ([48528e1](https://github.com/swimlane/pyattck/commit/48528e18f3a37a9d863586bd779bcfe906b158d7))
* Updating campaigns tests ([58a2c3d](https://github.com/swimlane/pyattck/commit/58a2c3da2863a6628c6490f75a4cd31861adbb1a))

## 7.0.0 - 2022-08-18

    - Added an interactive console menu system. You can access it by using the --interactive flag.

## 6.1.0 - 2022-06-13

    - Updated to pyattck-data 2.1.0

## 6.0.0 - 2022-06-09

    - BREAKING CHANGE RELEASE
        - Complete revamp and removed 70% of code base
    - CONSIDER THIS A NEW VERSION

## 5.4.0 - 2022-04-04

    - Added access to malwares from techniques (thanks aacienfuegos)
    - Access deprecated attribute from all MITRE ATT&CK objects (thanks aacienfuegos)
    - Updated documentation
    - Improved support of ICS framework (thanks cohmoti)
    - Bumped minor version

## 5.0.0 - 2021-10-22

    - Added new V10 data sources support
    - Added ICS Framework
    - Documentation updates

## 2.1.0 - 2020-08-25

    - Fixed issue with mitigations not being accessible in enterprise techniques
    - Added ability to access nested subtechniques (or not) using 
      nested_techniques parameter when instantiating Attck object

## 2.0.5 - 2020-05-19

    - Fixed relationship links in enterprise malwares and techniques
    - Fixed retrieval of id property in preattack actors
    - Updated methods _set_wiki, _set_id, and _set_reference in each frameworks base classes

## 2.0.4 - 2020-05-15

    - Updated pendulum requirements version to have max version
    
## 2.0.3 - 2020-05-15 

    - Updating pendulum requirements version

## 2.0.2 - 2020-05-08

    - Updated and modified docstrings across package

## 2.0.1 - 2020-05-06

    - Fixed issue with pre-attack and mobile attack technique id mappings

## 2.0.0 - 2020-02-14
    
    - Major update which includes external datasets to add additional context to MITRE ATT&CK
    - Restructured and created enterprise object type for future expansion into other MITRE ATT&CK Frameworks
    - Improved access and speed when accessing relationship objects
    - Added configuration settings and optional loading of datasets from local file paths

## 1.0.3

    - Fixed issue with appending techniques correctly

## 1.0.2

    - Updated Documentation

## 1.0.1

    - Updating Documentation with new reference links

## 1.0.0
    
    - Initial release of pyattck to PyPi
