# Attck

This documentation provides details about the main entry point called `Attck` within the `pyattck` package.

This class provides access to the MITRE Enterprise, PRE-ATT&CK, Mobile, and ICS Frameworks.

* MITRE Enterprise ATT&CK Framework
* MITRE PRE-ATT&CK Framework
* MITRE Mobile ATT&CK Framework
* MITRE ICS ATT&CK Framework

By default, `subtechniques` are accessible under each technique object.

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

You can turn this behavior off by passing `nested_subtechniques=False` when creating your `Attck` object. When turning this feature off you can access subtechniques on the same level as all other techniques.  Here's an example:

```python
from pyattck import Attck

attack = Attck()

for technique in attack.enterprise.techniques:
    print(technique.id)
    print(technique.name)
    print(f"checking if technique is subtechnique: {technique.subtechnique}")
```

## Attck Class

```eval_rst
.. autoclass:: pyattck.attck.Attck
   :members:
   :undoc-members:
   :show-inheritance:
```

```eval_rst
.. toctree::
   
   configuration
   datasets
```