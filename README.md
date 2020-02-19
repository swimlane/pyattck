# pyattck

[![Documentation Status](https://readthedocs.org/projects/pyattck/badge/?version=latest)](https://pyattck.readthedocs.io/en/latest/?badge=latest)

# Welcome to pyattck's documentation!

```
    .______   ____    ____  ___   .___________.___________.  ______  __  ___ 
    |   _  \  \   \  /   / /   \  |           |           | /      ||  |/  / 
    |  |_)  |  \   \/   / /  ^  \ `---|  |----`---|  |----`|  ,----'|  '  /  
    |   ___/    \_    _/ /  /_\  \    |  |        |  |     |  |     |    <   
    |  |          |  |  /  _____  \   |  |        |  |     |  `----.|  .  \  
    | _|          |__| /__/     \__\  |__|        |__|      \______||__|\__\ 
                                                                 
```

	A Python package to interact with the MITRE ATT&CK Framework

**pyattck** is a light-weight framework for the MITRE ATT&CK Framework.  This package extracts details about MITRE ATT&CK Tactics, Techniques, Actors/Groups, Tools, Malware, and Mitigations provided by MITRE.

## FEATURES

* Retrieve all Tactics, Techniques, Actors, Malware, Tools, and Mitigations from the MITRE ATT&CK Enterprise framework independently 
* Every data point has exposed properties that allow the user to retrieve additional data based on relationships:
* All techniques (if applicable) now have collected data from third-party resources that are accessible via properties on a technique.  These properties and values are:
	* command_list = A list of commands from multiple open-source tools and repositories that contain potential commands used by a technique
	* commands = A list of property objects that contain the `Name`, `Source, and `Command` dataset
	* queries = A list of potential queries for different products to identify threats within your environment by technique
	* datasets = A list of the datasets as it relates to a technique
	* possible_detections =  A list of potential detections for different products (e.g. NSM rules) as it relates to a technique
	* For more detailed information about these features, please view the following  [Generated Datasets](generateattcks/README.md)
* Each Actor object (if available) enables you to access the following properties on the object or access the entire dataset using the `external_dataset` property:
    * country
    * operations
    * attribution_links
    * known_tools
    * targets
    * additional_comments
    * external_description
* Each Tools object (if available) enables you to access the following properties on the object or access the entire dataset using the `external_dataset` property:
    * additional_names
    * attribution_links
    * additional_comments
    * family
* You can update/sync the external datasets by calling the `update()` method on an `Attck` object.  By default it will check for updates every 30 days.
* You can specify a local file path for the MITRE ATT&CK Enterprise Framework json, Generated Dataset, and/or a config.yml file.
* You can retrieve, if available, a image_logo of an actor or alternatively a ascii_logo will be generated.
* You can also search the external dataset for external commands that are similar using the `search_commands` method.

```python
from pyattck import Attck

attck = Attck()

for search in attck.enterprise.search_commands('powershell'):
		print(search['technique'])
		print(search['reason_for_match'])
```


* [Actor](enterprise/actor.md)
	* Tools used by the Actor or Group
	* Malware used by the Actor or Group
	* Techniques this Actor or Group uses
	* Retrieve a logo for an actor using either image_logo or ascii_logo properties
* [Malware](enterprise/malware.md)
    * Actor or Group(s) using this malware
    * Techniques this malware is used with
* [Mitigation](enterprise/mitigation.md)
    * Techniques related to a specific set of mitigation suggestions
* [Tactic](enterprise/tactic.md)
    * Techniques found in a specific Tactic (phase)
* [Technique](enterprise/technique.md)
    * Tactics a technique is found in
    * Mitigation suggestions for a given technique
    * Actor or Group(s) identified as using this technique
    * command_list = A list of commands from multiple open-source tools and repositories that contain potential commands used by a technique
    * commands = A list of property objects that contain the `Name`, `Source, and `Command` dataset
    * queries = A list of potential queries for different products to identify threats within your environment by technique
    * datasets = A list of the datasets as it relates to a technique
    * possible_detections =  A list of potential detections for different products (e.g. NSM rules) as it relates to a technique
* [Tools](enterprise/tools.md)
    * Techniques that the specified tool is used within
    * Actor or Group(s) using a specified tool



## Installation

OS X & Linux:

```sh
pip install pyattck
```

Windows:

```sh
pip install pyattck
```

### Installing from source

```bash
git clone git@github.com:swimlane/pyattck.git
cd pyattck
python setup.py install
```

### Prerequisites

The following libraries are required and installed by pyattck

```
requests
pendulum
pyfiglet
PyYaml
Pillow
```

## Usage example

To use **pyattck** you must instantiate a **Attck** object:

```python
from pyattck import Attck

attack = Attck()
```

Once you have a `Attck` object you can access the MITRE ATT&CK Enterprise framework's [Tactic](enterprise/tactic.md), [Technique](enterprise/technique.md), [Actor](enterprise/actor.md), [Malware](enterprise/malware.md), [Mitigation](enterprise/mitigation.md), and [Tools](enterprise/tools.md) using this object (as well as objects that are related to them).

### Specifying an alternate storage location

You can also specify an alternate location of different file objects.

You can specify the path of an `attck_json` as well as `dataset_json` when instantiating a `Attck` object.

Additionally, you can specify the location of a configuration file using `config_path` which must be a yaml file.

   > Please note that if you use this parameter you will need to reference this path the next time you instantiate an Attck object to use these datasets.

Storing and loading datasets from an alternate location

```python
from pyattck import Attck

attack = Attck(attck_json='/Users/{profile_name}/Desktop/attck_json.json', dataset_json='/Users/{profile_name}/Desktop/dataset_json.json')
```

Specifying an alternate location for a config.yml file:

```python
from pyattck import Attck

attack = Attck(config_path='/Users/{profile_name}/Desktop/config.yml')
```

You can access the following `main` properties on your **Attck** object:

* enterprise

Once specifying the MITRE ATT&CK Framework of your choosing, you can access additional properties.

Here are the properties under the [Enterprise](enterprise/enterprise.md) property:

* actor
* malware
* mitigation
* tactic
* technique
* tools

You can find more information about each property under the `enterprise` property here [Enterprise Documentation](enterprise/enterprise.md)

We understand that there are many different open-source projects being released, even on a daily basis but we wanted to provide a straightforward Python package that allowed the user to identify known relationships between all verticals of the MITRE ATT&CK Framework.

If you are unfamiliar with the MITRE ATT&CK Framework, there are a few key components to ensure you have a firm grasp around.  The first is Tactics & Techniques.  When looking at the MITRE ATT&CK Framework, the Tactics are the columns and represent the different phases of an attack.  

   > The MITRE ATT&CK Framework is NOT an all encompassing/defacto security coverage map - it is rather a FRAMEWORK and other avenues should be considered when assessing your security posture.

Techniques are the rows and categorized underneath specific tactics (columns).  The Techniques are data points within the framework that provides guidance when assessing your security gaps.  Additionally, Techniques (most) contain mitigation guidance but they also contain information about their relationship to tools, malware, even actors/groups that are/have used this technique during recorded attacks.  

This means, if your organization is focused on TTPs (Tactics Techniques and Procedures) used by certain actors/groups then MITRE ATT&CK Framework is perfect for you.  If you are not at this security maturing within your organization, no worries!  The ATT&CK Framework still provides really good guidance in a simple and straightforward layout, but programmatically it is not straightforward--especially if you wanted to measure (or map) your security controls using the framework.


### Development

You can use the provided [Dockerfile](../Dockerfile) to get a development and testing environment up and running for `pyattck`.

To use the `Dockerfile` run, cd to this repositories directory and run:

```
docker build --force-rm -t pyattck .
```

Once it is built, then run the docker container:

```
docker run pyattck
```

Running this will call the test python file in [bin/test.py](https://github.com/swimlane/pyattck/blob/master/bin/test.py).  Modify this file for additional testing and development.

## Running the tests

Tests within this project should cover all available properties and methods.  As this project grows the tests will become more robust but for now we are testing that they exist and return outputs.

## Contributing

Please read [CONTRIBUTING.md](https://github.com/swimlane/pyattck/blob/master/CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests to us.

## Versioning

We use [SemVer](http://semver.org/) for versioning. 

## Change Log

Please read [CHANGELOG.md](https://github.com/swimlane/pyattck/blob/master/CHANGELOG.md) for details on features for a specific version of `pyattck`

## Authors

* Josh Rickard - *Initial work* - [MSAdministrator](https://github.com/msadministrator)

See also the list of [contributors](https://github.com/swimlane/pyattck/contributors) who participated in this project.

## License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/swimlane/pyattck/blob/master/LICENSE.md) file for details

## Acknowledgments

First of all, I would like to thank everyone who contributes to open-source projects, especially the maintainers and creators of these projects.  Without them, this capability would not be possible.

This data set is generated from many different sources. As we continue to add more sources, we will continue to add them here.  Again thank you to all of these projects.  In no particular order, `pyattck` utilizes data from the following projects:


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


```eval_rst
.. toctree::
   :maxdepth: 2
   :caption: Contents:
   
   enterprise/enterprise
   enterprise/actor
   enterprise/malware
   enterprise/mitigation
   enterprise/tactic
   enterprise/technique
   enterprise/tools
   dataset/dataset
   pyattck/attck
   pyattck/configuration
   pyattck/datasets
```