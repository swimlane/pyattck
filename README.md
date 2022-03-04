> # Please upgrade to pyattck 4.1.1 or greater. We have moved external data to S3 to reduce associated costs. 

> pip install pyattck --upgrade

![pyattck](https://github.com/swimlane/pyattck/workflows/Testing%20pyattck/badge.svg)
![](./images/ubuntu_support.svg)
![](./images/macos_support.svg)
![](./images/windows_support.svg)
![](./images/code_coverage.svg)

# Welcome to pyattck's Documentation

```
    .______   ____    ____  ___   .___________.___________.  ______  __  ___
    |   _  \  \   \  /   / /   \  |           |           | /      ||  |/  /
    |  |_)  |  \   \/   / /  ^  \ `---|  |----`---|  |----`|  ,----'|  '  /
    |   ___/    \_    _/ /  /_\  \    |  |        |  |     |  |     |    <
    |  |          |  |  /  _____  \   |  |        |  |     |  `----.|  .  \
    | _|          |__| /__/     \__\  |__|        |__|      \______||__|\__\

```
	A Python package to interact with MITRE ATT&CK Frameworks

> Current Version is 5.4.0

**pyattck** is a light-weight framework for MITRE ATT&CK Frameworks. This package extracts details from the MITRE Enterprise, PRE-ATT&CK, Mobile, and ICS Frameworks.

## Why?

`pyattck` assist organizations and individuals with accessing MITRE ATT&CK Framework(s) in a programmatic way. Meaning, you can access all defined actors, malwares, mitigations, tactics, techniques, and tools defined by the Enterprise, Mobile, Pre-Attck, and ICS frameworks via a command-line utility or embedding into your own code base.

There are many reasons why you would want to access this data in an automated (scripted/coded) way but a few examples are:

* Generate reports with additional details about a technique (or any object defined in the framework) 
* A build pipeline of detection rules with additional MITRE ATT&CK details for categorization
* Quickly searching for specific details about a technique without navigating a web page

There are other benefits that `pyattck` provide as well which includes the ability to provide additional contextual data. You can find more information about this data [here](https://github.com/swimlane/pyattck-data) but the basics are that `pyattck` utilizes multiple open-source repositorties to gather additional contextual data like commands used to execute a technique, country and other details about a malicious actor, other variants of malware similar to a defined tool/malware, etc. 

This additional context is what makes `pyattck` truly powerful and enables people to build more robust testing and validation of their detection rules, validates testing assumptions, etc. Truly there are countless ways that `pyattck` could be utilized to help blue, red, and purple teams defend organizations (and themselves).

## Features

The **pyattck** package retrieves all Tactics, Techniques, Actors, Malware, Tools, and Mitigations from the MITRE ATT&CK Frameworks as well as any defined relationships within the MITRE ATT&CK dataset.

In addition, Techniques, Actors, and Tools (if applicable) now have collected data from third-party resources that are accessible via properties on a technique. For more detailed information about these features, see [External Datasets](docs/dataset/dataset.md).

The **pyattck** package allows you to:

  * Specify a URL or local file path for the MITRE ATT&CK Enterprise Framework json, generated dataset, and/or a config.yml file.
  * Search the external dataset for external commands that are similar using `search_commands`.
  * Access data from the MITRE PRE-ATT&CK Framework
  * Access data from the MITRE Mobile ATT&CK Framework
  * Access data from the MITRE ICS ATT&CK Framework
  * Access subtechniques as nested objects or you can turn it off and access as normal technique
  * Access compliance controls (currently NIST 800-53) related to a MITRE ATT&CK Technique

# Table of Contents

1. [Installation](#installation)
2. [Usage Example](#usage-example)
3. [Configuration](#configuration)
4. [Notes](#note)

## Installation

You can install **pyattack** on OS X, Linux, or Windows. You can also install it directly from the source. To install, see the commands under the relevant operating system heading, below.

### Prerequisites

The following libraries are required and installed by pyattck:

```
requests
PyYaml>=5.4.1
fire==0.3.1
attrs==21.2.0
```

### macOS, Linux and Windows:

```bash
pip install pyattck
```

### Installing from source

```bash
git clone https://github.com/swimlane/pyattck.git
cd pyattck
python setup.py install
```

## Usage example

To use **pyattck** you must instantiate an **Attck** object. Although you can interact directly with each class, the intended use is through a **Attck** object:

```python
from pyattck import Attck

attack = Attck()
```

By default, `subtechniques` are accessible under each technique object. You can turn this behavior off by passing `nested_subtechniques=False` when creating your `Attck` object.

As an example, the default behavior looks like the following example:

```python
from pyattck import Attck

attack = Attck()

for technique in attack.enterprise.techniques:
    print(technique.id)
    print(technique.name)
    for subtechnique in technique.subtechniques:
        print(subtechnique.id)
        print(subtechnique.name)
```

You can access the following `main` properties on your **Attck** object:

* enterprise
* preattack
* mobile
* ics

Once you specify the MITRE ATT&CK Framework, you can access additional properties.

Here are the accessible objects under the [Enterprise](docs/enterprise/enterprise.md) property:

* [actors](docs/enterprise/actor.md)
* [controls](docs/enterprise/control.md)
* [malwares](docs/enterprise/malware.md)
* [mitigations](docs/enterprise/mitigation.md)
* [tactics](docs/enterprise/tactic.md)
* [techniques](docs/enterprise/technique.md)
* [tools](docs/enterprise/tools.md)

For more information on object types under the `enterprise` property, see [Enterprise](docs/enterprise/enterprise.md).

Here are the accessible objects under the [PreAttck](docs/preattck/preattck.md) property:

* [actors](docs/preattck/actor.md)
* [tactics](docs/preattck/tactic.md)
* [techniques](docs/preattck/technique.md)

For more information on object types under the `preattck` property, see [PreAttck](docs/preattck/preattck.md).

Here are the accessible objects under the [Mobile](docs/mobile/mobileattck.md) property:

* [actors](docs/mobile/actor.md)
* [malwares](docs/mobile/malware.md)
* [mitigations](docs/mobile/mitigation.md)
* [tactics](docs/mobile/tactic.md)
* [techniques](docs/mobile/technique.md)
* [tools](docs/mobile/tools.md)

For more information on object types under the `mobile` property, see [Mobile](docs/mobile/mobileattck.md).

Here are the accessible objects under the [ICS](docs/ics/icsattck.md) property:

* [controls](docs/ics/control.md)
* [malwares](docs/ics/malware.md)
* [mitigations](docs/ics/mitigation.md)
* [tactics](docs/ics/tactic.md)
* [techniques](docs/ics/technique.md)

For more information on object types under the `ics` property, see [ICS](docs/ics/icsattck.md).

## Configuration

`pyattck` allows you to configure if you store external data and where it is stored. 

```python
from pyattck import Attck

attck = Attck(
    nested_subtechniques=True,
    use_config=False,
    save_config=False,
    config_file_path='~/pyattck/config.yml',
    data_path='~/pyattck/data',
    enterprise_attck_json="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
    pre_attck_json="https://raw.githubusercontent.com/mitre/cti/master/pre-attack/pre-attack.json",
    mobile_attck_json="https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json",
    ics_attck_json="https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json",
    nist_controls_json="https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-control-framework-mappings/main/frameworks/attack_10_1/nist800_53_r4/stix/nist800-53-r4-controls.json",
    generated_attck_json="https://swimlane-pyattck.s3.us-west-2.amazonaws.com/generated_attck_data.json",
    generated_nist_json="https://swimlane-pyattck.s3.us-west-2.amazonaws.com/attck_to_nist_controls.json",
    **kwargs
)
```

By default, `pyattck` will (now) pull the latest external data from their respective locations using HTTP GET requests. `pyattck` currently pulls from the following locations:

* enterprise_attck_json="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
* pre_attck_json="https://raw.githubusercontent.com/mitre/cti/master/pre-attack/pre-attack.json"
* mobile_attck_json="https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json"
* ics_attck_json="https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json"
* nist_controls_json="https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-control-framework-mappings/main/frameworks/attack_10_1/nist800_53_r4/stix/nist800-53-r4-controls.json"
* generated_attck_json="https://swimlane-pyattck.s3.us-west-2.amazonaws.com/generated_attck_data.json"
* generated_nist_json="https://swimlane-pyattck.s3.us-west-2.amazonaws.com/attck_to_nist_controls.json"

You have several options when instantiating the `Attck` object. As of `4.0.0` you can now specify any of the following options:

* use_config - When you specify this argument as `True` pyattck will attempt to retrieve the configuration specified in the `config_file_path` location. If this file is corrupted or cannot be found, we will default to retrieving data from the specified `*_attck_json` locations.
* save_config - When you specify this argument as `True` pyattck will save the configuration file to the specified location set by `config_file_path`. Additionally, we will save all downloaded files to the `data_path` location specified. If you have specified a local path location instead of a download URL for any of the `*_attck_json` parameters we will save this location in our configuration and reference this location going forward. 
* config_file_path - The path to store a configuration file. Default is `~/pyattck/config.yml`
* data_path - The path to store any data files downloaded to the local system. Default is `~/pyattck/data`

### JSON Locations

Additionally, you can specify the location for each individual `*_attck_json` files by passing in either a URI or a local file path. If you have passed in a local file path, we will simply read from this file. 

If you have used the default values or specified an alternative URI location to retrieve these JSON files from, you can additionally pass in `**kwargs` that will be passed along to the `Requests` python package when performing any HTTP requests.

## Note

We understand that there are many different open-source projects being released, even on a daily basis, but we wanted to provide a straightforward Python package that allowed the user to identify known relationships between all verticals of the MITRE ATT&CK Framework.

If you are unfamiliar with the MITRE ATT&CK Framework, there are a few key components to ensure you have a firm grasp around. The first is Tactics & Techniques. When looking at the [MITRE ATT&CK Framework](https://attack.mitre.org/), the Tactics are the columns and represent the different phases of an attack.

   > The MITRE ATT&CK Framework is NOT an all encompassing/defacto security coverage map - it is rather a FRAMEWORK and additional avenues should also be considered when assessing your security posture.

Techniques are the rows of the framework and are categorized underneath specific Tactics (columns). They are data points within the framework that provides guidance when assessing your security gaps. Additionally, (most) Techniques contain mitigation guidance in addition to information about their relationship to tools, malware, and even actors/groups that have used this technique during recorded attacks.

This means, if your organization is focused on TTPs (Tactics Techniques and Procedures) used by certain actors/groups then MITRE ATT&CK Framework is perfect for you. If you are not at this security maturing within your organization, no worries! The ATT&CK Framework still provides really good guidance in a simple and straightforward layout, but programmatically it is not straightforward--especially if you wanted to measure (or map) your security controls using the framework.

### Developing and Testing

You can add features or bugs or run the code in a development environment.

1. To get a development and testing environment up and running, use this [Dockerfile](https://github.com/swimlane/pyattck/blob/master/Dockerfile).

2. To use the `Dockerfile` run, cd to this repository directory and run:

  ```
  docker build --force-rm -t pyattck .
  ```

3. Next, run the docker container:

  ```
  docker run pyattck
  ```

  Running this calls the test python file in [bin/test.py](https://github.com/swimlane/pyattck/blob/master/bin/test.py).

4. Modify the test python file for additional testing and development.

## Running the tests

Tests within this project should cover all available properties and methods. As this project grows the tests will become more robust but for now we are testing that they exist and return outputs.

## Contributing

Please read [CONTRIBUTING.md](https://github.com/swimlane/pyattck/blob/master/CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests to us.

## Versioning

We use [SemVer](http://semver.org/) for versioning.

## Change Log

For details on features for a specific version of `pyattck`, see the [CHANGELOG.md](https://github.com/swimlane/pyattck/blob/master/CHANGELOG.md).

## Authors

* Josh Rickard - *Initial work* - [MSAdministrator](https://github.com/msadministrator)

See also the list of [contributors](https://github.com/swimlane/pyattck/contributors).

## License

This project is licensed under the [MIT License](https://github.com/swimlane/pyattck/blob/master/LICENSE.md).

## Acknowledgments

First of all, I would like to thank everyone who contributes to open-source projects, especially the maintainers and creators of these projects. Without them, this capability would not be possible.

This data set is generated from many different sources. As we continue to add more sources, we will continue to add them here. Again thank you to all of these projects. In no particular order, `pyattck` utilizes data from the following projects:


* [Mitre ATT&CK APT3 Adversary Emulation Field Manual](https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx)
* [Atomic Red Team (by Red Canary)](https://github.com/redcanaryco/atomic-red-team)
* [Atomic Threat Coverage](https://github.com/atc-project/atomic-threat-coverage)
* [attck_empire (by dstepanic)](https://github.com/dstepanic/attck_empire)
* [sentinel-attack (by BlueTeamLabs)](https://github.com/BlueTeamLabs/sentinel-attack)
* [Litmus_test (by Kirtar22)](https://github.com/Kirtar22/Litmus_Test)
* [nsm-attack (by oxtf)](https://github.com/0xtf/nsm-attack)
* [osquery-attck (by teoseller)](https://github.com/teoseller/osquery-attck)
* [Mitre Stockpile](https://github.com/mitre/stockpile)
* [SysmonHunter (by baronpan)](https://github.com/baronpan/SysmonHunter)
* [ThreatHunting-Book (by 12306Bro)](https://github.com/12306Bro/Threathunting-book)
* [threat_hunting_tables (by dwestgard)](https://github.com/dwestgard/threat_hunting_tables)
* [APT Groups & Operations](https://docs.google.com/spreadsheets/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU/edit#gid=1864660085)
* [C2Matrix (by @jorgeorchilles, @brysonbort, @adam_mashinchi)](https://www.thec2matrix.com/)
* [Elemental](https://github.com/Elemental-attack/Elemental)
* [MalwareArchaeology - ATTACK](https://github.com/MalwareArchaeology/ATTACK)
* [Attack-Technique-Dataset](https://github.com/NewBee119/Attack-Technique-Dataset)


```eval_rst
.. toctree::
   :titlesonly:

   configuration
   pyattck/attck
   Dataset <https://github.com/swimlane/pyattck-data>
   enterprise/enterprise
   preattck/preattck
   mobile/mobileattck
   ics/icsattck
```
