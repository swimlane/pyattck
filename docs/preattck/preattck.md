# PreAttck

This documentation provides details about the PreAttck class within the `pyattck` package.

The PreAttck class provides detailed information about data within the MITRE PRE-ATT&CK framework

Each of the `main` properties (above) can return a json object of the entire object or you can access each property individually.  An example of this is here:

```python
from pyattck import Attck

attack = Attck()

# accessing techniques and their properties
for technique in attack.preattack.techniques:
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

The following is only a small sample of the available properties on each object and each object type (actors, tactics, and techniques) will have different properties that you can access.


* Every data point has exposed properties that allow the user to retrieve additional data based on relationships:
    * [Actor](actor.md)
        * Relationship Objects
            * Techniques this Actor or Group uses
        * External Data
            * country which this actor or group may be associated with (attribution is hard)
            * operations 
            * attribution_links
            * known_tools
            * targets
            * additional_comments
            * external_description
    * [Tactic](tactic.md)
        * Techniques found in a specific Tactic (phase)
    * [Technique](technique.md)
        * Relationship Objects
            * Tactics a technique is found in
            * Actor or Group(s) identified as using this technique


Below shows you how you can access each of object types and their properties.  Additionally, you can access related object types associated with this selected object type:

```python
from pyattck import Attck

attack = Attck()

for actor in attack.preattack.actors:
    print(actor.id)
    print(actor.name)

    # accessing techniques used by an actor or group
    for technique in actor.techniques:
        print(technique.id)
        print(technique.name)

# accessing tactics
for tactic in attack.preattack.tactics:
    print(tactic.id)
    print(tactic.name)

    # accessing techniques related to this tactic
    for technique in tactic.techniques:
        print(technique.id)
        print(technique.name)

# accessing techniques
for technique in attack.preattack.techniques:
    print(technique.id)
    print(technique.name)

    # accessing tactics that this technique belongs to
    for tactic in technique.tactics:
        print(tactic.id)
        print(tactic.name)

    # accessing actors using this technique
    for actor in technique.actors:
        print(actor.id)
        print(actor.name)
```

## PreAttck Class

```eval_rst
.. autoclass:: pyattck.preattck.preattck.PreAttck
   :members:
   :undoc-members:
   :show-inheritance:
```


```eval_rst
.. toctree::
   
   actor
   tactic
   technique
```
