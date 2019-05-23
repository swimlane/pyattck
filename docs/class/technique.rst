******************
Technique
******************

This documentation provides details about the AttckTechnique class within the `pyattck` package.

This class provides information about the techniques found under each tactic (columns) within the Mitre ATT&CK Framework.  Additionally, a AttckTechnique object allows the user to access additional relationships within the Mitre ATT&CK Framework:

* Tactics a technique is found in
* Mitigation suggestions for a given technique
* Actor or Group(s) identified as using this technique

.. autoclass:: pyattck.AttckTechnique
   :members:
   :show-inheritance: