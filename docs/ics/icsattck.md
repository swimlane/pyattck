# ICS (Industrial Control Systems)

This documentation provides details about the ICSAttck class within the `pyattck` package.

The ICSAttck class provides detailed information about data within the ICS MITRE ATT&CK framework

Each of the `main` properties (above) can return a json object of the entire object or you can access each property individually.  An example of this is here:

```python
from pyattck import Attck

attack = Attck()

# accessing techniques and their properties
for technique in attack.ics.techniques:
	# if you want to return individual properties of this object you call them directly
	print(technique.id)
	print(technique.name)
	print(technique.alias)
	print(technique.description)
	print(technique.stix)
	print(technique.platforms)
	print(technique.permissions)
	print(technique.wiki)
	.....
```

The following is only a small sample of the available properties on each object and each object type (malware, mitigations, tactics, and techniques) will have different properties that you can access.


* Every data point has exposed properties that allow the user to retrieve additional data based on relationships:
    * [Malware](malware.md)
        * Techniques this malware is used with
    * [Mitigation](mitigation.md)
        * Techniques related to a specific set of mitigation suggestions
    * [Tactic](tactic.md)
        * Techniques found in a specific Tactic (phase)
    * [Technique](technique.md)
        * Relationship Objects
            * Tactics a technique is found in
            * Mitigation suggestions for a given technique
        * External Data
            * command_list - A list of commands from multiple open-source tools and repositories that contain potential commands used by a technique
            * commands - A list of property objects that contain the `Name`, `Source, and `Command` dataset
            * queries - A list of potential queries for different products to identify threats within your environment by technique
            * datasets - A list of the datasets as it relates to a technique
            * possible_detections -  A list of potential detections for different products (e.g. NSM rules) as it relates to a technique
            * For more detailed information about these features, please view the following  [External Datasets](../dataset/dataset.md)


Below shows you how you can access each of object types and their properties.  Additionally, you can access related object types associated with this selected object type:

```python
from pyattck import Attck

attack = Attck()

# accessing malware
for malware in attack.ics.malwares:
    print(malware.id)
    print(malware.name)

    # accessing techniques that this malware is used in
    for technique in malware.techniques:
        print(technique.id)
        print(technique.name)

# accessing mitigation
for mitigation in attack.ics.mitigations:
    print(mitigation.id)
    print(mitigation.name)

    # accessing techniques related to mitigation recommendations
    for technique in mitigation.techniques:
        print(technique.id)
        print(technique.name)
        # you can also access generated data sets on aa technique
        print(technique.command_list)
        print(technique.commands)
        print(technique.queries)
        print(technique.datasets)
        print(technique.possible_detections)

# accessing tactics
for tactic in attack.ics.tactics:
    print(tactic.id)
    print(tactic.name)

    # accessing techniques related to this tactic
    for technique in tactic.techniques:
        print(technique.id)
        print(technique.name)
        # you can also access generated data sets on aa technique
        print(technique.command_list)
        print(technique.commands)
        print(technique.queries)
        print(technique.datasets)
        print(technique.possible_detections)

# accessing techniques
for technique in attack.ics.techniques:
    print(technique.id)
    print(technique.name)
    # you can also access generated data sets on aa technique
    print(technique.command_list)
    print(technique.commands)
    print(technique.queries)
    print(technique.datasets)
    print(technique.possible_detections)

    # accessing tactics that this technique belongs to
    for tactic in technique.tactics:
        print(tactic.id)
        print(tactic.name)

    # accessing mitigation recommendations for this technique
    for mitigation in technique.mitigations:
        print(mitigation.id)
        print(mitigation.name)
```

## ICSAttck Class

```eval_rst
.. autoclass:: pyattck.ics.icsattck.ICSAttck
   :members:
   :undoc-members:
   :show-inheritance:
```


```eval_rst
.. toctree::
   
   control
   malware
   mitigation
   tactic
   technique
```
