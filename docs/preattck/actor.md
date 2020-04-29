# PreAttckActor

This documentation provides details about PreAttckActor class within the `pyattck` package.

The `PreAttckActor` class provides detailed information about identified actors & groups within the MITRE PRE-ATT&CK Framework.  Additionally, an `PreAttckActor` object allows the user to access additional relationships within the MITRE PRE-ATT&CK Framework:

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

An additional fun feature is that you can now retrieve a logo for a actor.  Currently, a limited set of logos are provided.
If a logo is not provided, then `pyattck` will generate one using ascii art.

You can access these logos using the following properties:

* ascii_logo

## PreAttckActor Class

```eval_rst
.. autoclass:: pyattck.preattck.actor.PreAttckActor
   :members:
   :undoc-members:
   :show-inheritance:
```
