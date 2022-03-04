# MobileAttckTechnique

This documentation provides details about the `MobileAttckTechnique` class within the `pyattck` package.

This class provides information about the techniques found under each tactic (columns) within the MITRE Mobile ATT&CK Framework.  Additionally, a `MobileAttckTechnique` object allows the user to access additional relationships within the MITRE Mobile ATT&CK Framework:

* Tactics a technique is found in
* Mitigation suggestions for a given technique
* Actor or Group(s) identified as using this technique
* Tools used with a given technique
* Malware used with a given technique
* Data Components of a technique
* Data Sources of a technique

Each technique enables you to access the following properties on the object:

* command_list - A list of commands associated with a technique
* commands = A list of dictionary objects containing source, command, and provided name associated with a technique
* queries = A list of dictionary objects containing product, query, and name associated with a technique
* datasets = A list of raw datasets associated with a technique
* possible_detections = A list of raw datasets containing possible detection methods for a technique


## MobileAttckTechnique Class

```eval_rst
.. autoclass:: pyattck.mobile.technique.MobileAttckTechnique
   :members:
   :undoc-members:
   :show-inheritance:
```