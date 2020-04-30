# MobileAttckActor

This documentation provides details about MobileAttckActor class within the `pyattck` package.

The `MobileAttckActor` class provides detailed information about identified actors & groups within the MITRE Mobile ATT&CK Framework.  Additionally, an `MobileAttckActor` object allows the user to access additional relationships within the MITRE Mobile ATT&CK Framework:

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

An additional fun feature is that you can now retrieve a logo for a actor.  Currently, a limited set of logos are provided.
If a logo is not provided, then `pyattck` will generate one using ascii art.

You can access these logos using the following properties:

* ascii_logo

## MobileAttckActor Class

```eval_rst
.. autoclass:: pyattck.mobile.actor.MobileAttckActor
   :members:
   :undoc-members:
   :show-inheritance:
```
