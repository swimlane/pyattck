# Actor

This documentation provides details about Actor class within the `pyattck` package.

The `AttckActor` class provides detailed information about identified actors & groups within the MITRE ATT&CK Framework.  Additionally, an `AttckActor` object allows the user to access additional relationships within the MITRE ATT&CK Framework:

* Tools used by the Actor or Group
* Malware used by the Actor or Group
* Techniques this Actor or Group uses

You can also access external data properties. The following properties are generated using external data:

* country
* operations
* attribution_links
* known_tools
* targets
* additional_comments
* external_description

You can retrieve the entire dataset using the `external_dataset` property.

## AttckActor Class

```eval_rst
.. autoclass:: pyattck.enterprise.actor.AttckActor
   :members:
   :undoc-members:
   :show-inheritance:
```
