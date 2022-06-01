# Technique

This documentation provides details about the `Technique` class within the `pyattck` package.

> The `Technique` object is based on the following [data model](https://github.com/swimlane/pyattck-data-models/blob/main/src/pyattck_data_models/technique.py)

This class provides information about the techniques found under each tactic (columns) within the MITRE ATT&CK Frameworks.
Additionally, a `Technique` object allows the user to access additional relationships within the MITRE ATT&CK Frameworks:

* Tactics a technique is found in
* Mitigation suggestions for a given technique
* Actor or Group(s) identified as using this technique
* Tools used with a given technique
* Malware used with a given technique
* Subtechniques of a technique if `nested_subtechniques` is set to `True`
* NIST 800-53 Controls related to a technique
* Data Components of a technique
* Data Sources of a technique

Each technique enables you to access the following properties on the object:

* command_list - A list of commands associated with a technique
* commands = A list of dictionary objects containing source, command, and provided name associated with a technique
* queries = A list of dictionary objects containing product, query, and name associated with a technique
* datasets = A list of raw datasets associated with a technique
* possible_detections = A list of raw datasets containing possible detection methods for a technique
* data_sources = A list of raw datasets containing data sources listed for the technique


## Technique Class

```eval_rst
.. autoclass:: pyattck_data_models.technique.Technique
   :members:
   :undoc-members:
   :show-inheritance:
```