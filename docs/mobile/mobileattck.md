# MobileAttck

This documentation provides details about the MobileAttck class within the `pyattck` package.

The MobileAttck class provides detailed information about data within the MITRE Mobile ATT&CK framework

Each of the `main` properties can return a json object of the entire object or you can access each property individually.  An example of this is here:

```python
from pyattck import Attck

attack = Attck()

# accessing techniques and their properties
for technique in attack.mobile.techniques:
	# if you want to return individual properties of this object you call them directly
	print(technique.id)
	print(technique.name)
	print(technique.alias)
	print(technique.description)
	print(technique.stix)
	print(technique.platforms)
	.....
```

The following is only a small sample of the available properties on each object and each object type (actors, malware, mitigations, tactics, techniques, and tools) will have different properties that you can access.


* Every data point has exposed properties that allow the user to retrieve additional data based on relationships:
    * [Actor](actor.md)
        * Relationship Objects
            * Tools used by the Actor or Group
            * Malware used by the Actor or Group
            * Techniques this Actor or Group uses
        * External Data
            * Retrieve a logo for an actor using ascii_logo properties
            * country which this actor or group may be associated with (attribution is hard)
            * operations 
            * attribution_links
            * known_tools
            * targets
            * additional_comments
            * external_description
    * [Malware](malware.md)
        * Actor or Group(s) using this malware
        * Techniques this malware is used with
    * [Mitigation](mitigation.md)
        * Techniques related to a specific set of mitigation suggestions
    * [Tactic](tactic.md)
        * Techniques found in a specific Tactic (phase)
    * [Technique](technique.md)
        * Relationship Objects
            * Tactics a technique is found in
            * Mitigation suggestions for a given technique
            * Actor or Group(s) identified as using this technique
        * External Data
            * command_list - A list of commands from multiple open-source tools and repositories that contain potential commands used by a technique
            * commands - A list of property objects that contain the `Name`, `Source, and `Command` dataset
            * queries - A list of potential queries for different products to identify threats within your environment by technique
            * datasets - A list of the datasets as it relates to a technique
            * possible_detections -  A list of potential detections for different products (e.g. NSM rules) as it relates to a technique
            * For more detailed information about these features, please view the following  [External Datasets](../dataset/dataset.md)
    * [Tools](tools.md)
        * Relationship Objects
            * Techniques that the specified tool is used within
            * Actor or Group(s) using a specified tool
        * External Data
            * additional_names for the specified tool
            * attribution_links associated with the specified tool
            * additional_comments about the specified tool
            * family of the specified tool



Below shows you how you can access each of object types and their properties.  Additionally, you can access related object types associated with this selected object type:

```python
from pyattck import Attck

attack = Attck()

for actor in attack.mobile.actors:
    print(actor.id)
    print(actor.name)

    # accessing malware used by an actor or group
    for malware in actor.malwares:
        print(malware.id)
        print(malware.name)

    # accessing tools used by an actor or group
    for tool in actor.tools:
        print(tool.id)
        print(tool.name)

    # accessing techniques used by an actor or group
    for technique in actor.techniques:
        print(technique.id)
        print(technique.name)
        # you can also access generated data sets on aa technique
        print(technique.command_list)
        print(technique.commands)
        print(technique.queries)
        print(technique.datasets)
        print(technique.possible_detections)

# accessing malware
for malware in attack.mobile.malwares:
    print(malware.id)
    print(malware.name)

    # accessing actor or groups using this malware
    for actor in malware.actors:
        print(actor.id)
        print(actor.name)

    # accessing techniques that this malware is used in
    for technique in malware.techniques:
        print(technique.id)
        print(technique.name)

# accessing mitigation
for mitigation in attack.mobile.mitigations:
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
for tactic in attack.mobile.tactics:
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
for technique in attack.mobile.techniques:
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

    # accessing actors using this technique
    for actor in technique.actors:
        print(actor.id)
        print(actor.name)

# accessing tools
for tool in attack.mobile.tools:
    print(tool.id)
    print(tool.name)

    # accessing techniques this tool is used in
    for technique in tool.techniques:
        print(technique.id)
        print(technique.name)
        # you can also access generated data sets on aa technique
        print(technique.command_list)
        print(technique.commands)
        print(technique.queries)
        print(technique.datasets)
        print(technique.possible_detections)

    # accessing actor or groups using this tool
    for actor in tool.actors:
        print(actor.id)
        print(actor.name)
```

## MobileAttck Class

```eval_rst
.. autoclass:: pyattck.mobile.mobileattck.MobileAttck
   :members:
   :undoc-members:
   :show-inheritance:
```


```eval_rst
.. toctree::
   
   actor
   malware
   mitigation
   tactic
   technique
   tools
```
