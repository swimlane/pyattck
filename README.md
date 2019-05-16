# pyattck

[![Documentation Status](https://readthedocs.org/projects/pyattck/badge/?version=latest)](https://pyattck.readthedocs.io/en/latest/?badge=latest)


A Python Module to interact with the Mitre ATT&CK Framework

**pyattck** has the following notable features in it's current release:

* Retrieve all Tactics, Techniques, Actors, Malware, Tools, and Mitigations
* All techniques have suggested mitigations as a property
* For each class you can access additional information about related data points:

* Actor
  * Tools used by the Actor or Group
  * Malware used by the Actor or Group
  * Techniques this Actor or Group uses
* Malware
  * Actor or Group(s) using this malware
  * Techniques this malware is used with
* Mitigation
  * Techniques related to a specific set of mitigation suggestions
* Tactic
  * Techniques found in a specific Tactic (phase)
* Technique
  * Tactics a technique is found in
  * Mitigation suggestions for a given technique
  * Actor or Group(s) identified as using this technique
* Tools
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

## Usage example

To use **pyattck** you must instantiate a **Attck** object:

```python
from pyattck import Attck

attack = Attck()
```

You can access the following properties on your **Attck** object:

* actor
* malware
* mitigation
* tactic
* technique
* tools

Below are examples of accessing each of these properties:

```python
from pyattck import Attck

attack = Attck()

# accessing actors
for actor in attack.actors:
    print(actor)
    
    # accessing malware used by an actor or group
    for malware in actor.malware:
        print(malware)

    # accessing tools used by an actor or group
    for tool in actor.tools:
        print(tool)

    # accessing techniques used by an actor or group
    for technique in actor.techniques:
        print(technique)

# accessing malware
for malware in attack.malwares:
    print(malware)

    # accessing actor or groups using this malware
    for actor in malware.actors:
        print(actor)

    # accessing techniques that this malware is used in
    for technique in malware.techniques:
        print(technique)

# accessing mitigation
for mitigation in attack.mitigations:
    print(mit)

    # accessing techniques related to mitigation recommendations
    for technique in mitigation.techniques:
        print(technique)

# accessing tactics
for tactic in attack.tactics:
    print(tactic)

    # accessing techniques related to this tactic
    for technique in tactic.techniques:
        print(technique)

# accessing techniques
for technique in attack.techniques:
    print(technique)

    # accessing tactics that this technique belongs to
    for tactic in technique.tactics:
        print(tactic)

    # accessing mitigation recommendations for this technique
    for mitigation in technique.mitigation:
        print(mitigation)

    # accessing actors using this technique
    for actor in technique.actors:
        print(actor)
    

# accessing tools
for tool in attack.tools:
    print(tool)

    # accessing techniques this tool is used in
    for technique in tool.techniques:
        print(technique)

    # accessing actor or groups using this tool
    for actor in tool.actors:
        print(actor)

```

## Release History

* 1.0.0
   * Initial release of pyattck to PyPi
* 1.0.1
   * Updating Documentation with new reference links

## Meta

Josh Rickard – [@MSAdministrator](https://twitter.com/MSAdministrator) – rickardja@live.com

Distributed under the MIT license. See ``LICENSE`` for more information.

## Contributing

1. Fork it (<https://github.com/swimlane/pyattck/fork>)
2. Create your feature branch (`git checkout -b feature/fooBar`)
3. Commit your changes (`git commit -am 'Add some fooBar'`)
4. Push to the branch (`git push origin feature/fooBar`)
5. Create a new Pull Request