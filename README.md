![pyattck](https://github.com/swimlane/pyattck/workflows/Testing%20pyattck/badge.svg)
![](./images/ubuntu_support.svg)
![](./images/macos_support.svg)
![](./images/windows_support.svg)

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


**pyattck** is a light-weight framework for MITRE ATT&CK Frameworks. This package extracts details from the MITRE Enterprise, PRE-ATT&CK, and Mobile Frameworks.

## Features

The **pyattck** package retrieves all Tactics, Techniques, Actors, Malware, Tools, and Mitigations from the MITRE ATT&CK Frameworks as well as any defined relationships within the MITRE ATT&CK dataset.
In addition, Techniques, Actors, and Tools (if applicable) now have collected data from third-party resources that are accessible via properties on a technique. For more detailed information about these features, see [External Datasets](docs/dataset/dataset.md).

The **pyattck** package allows you to:

  * Update or sync the external datasets by calling the `update()` method on an `Attck` object. By default it checks for updates every 30 days.
  * Specify a local file path for the MITRE ATT&CK Enterprise Framework json, generated dataset, and/or a config.yml file.
  * Retrieve an image_logo of an actor (when available). If an image_logo isn't available, it generates an ascii_logo.
  * Search the external dataset for external commands that are similar using `search_commands`.
  * Access data from the MITRE PRE-ATT&CK Framework
  * Access data from the MITRE Mobile ATT&CK Framework

## Installation

You can install **pyattack** on OS X, Linux, or Windows. You can also install it directly from the source. To install, see the commands under the relevant operating system heading, below.

### Prerequisites

The following libraries are required and installed by pyattck:

```
requests
pendulum>=1.2.3,<1.3
pyfiglet==0.8.post1
PyYaml>=5.0
Pillow==7.1.2
fire==0.3.1
```

### OS X & Linux:

```bash
pip install pyattck
```

### Windows:

```bash
pip install pyattck
```

### Installing from source

```bash
git clone git@github.com:swimlane/pyattck.git
cd pyattck
python setup.py install
```

## Usage example

To use **pyattck** you must instantiate an **Attck** object. Although you can interact directly with each class, the intended use is through a **Attck** object:

```python
from pyattck import Attck

attack = Attck()
```

By default, `subtechniques` are accessible under each technique object.  You can turn this behavior off by passing `nested_subtechniques=False` when creating your `Attck` object.

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

Once you specify the MITRE ATT&CK Framework, you can access additional properties.

Here are the accessible objects under the [Enterprise](docs/enterprise/enterprise.md) property:

* [actors](docs/enterprise/actor.md)
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

   pyattck/attck
   dataset/dataset
   enterprise/enterprise
   preattck/preattck
   mobile/mobileattck
```