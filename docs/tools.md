# Tools

This documentation provides details about the `Tool` class within the `pyattck` package.

> The `Tool` object is based on the following [data model](https://github.com/swimlane/pyattck-data-models/blob/main/src/pyattck_data_models/tool.py)

You can also access external data properties. The following properties are generated using external data:

   1. additional_names
   2. attribution_links
   3. additional_comments
   4. family

You can retrieve the entire dataset using the `external_dataset` property.

You can also access external data properties from the C2 Matrix project. The following properties are generated using C2 Matrix external data:

   - HTTP
   - Implementation
   - Custom Profile
   - DomainFront
   - Multi-User
   - SMB
   - Kill Date
   - macOS
   - GitHub
   - Key Exchange
   - Chaining
   - Price
   - TCP
   - Proxy Aware
   - HTTP3
   - HTTP2
   - Date
   - Evaluator
   - Working Hours
   - Slack
   - FTP
   - Version Reviewed
   - Logging
   - Name
   - License
   - Windows
   - Stego
   - Notes
   - Server
   - Actively Maint.
   - Dashboard
   - DNS
   - Popular Site
   - ICMP
   - IMAP
   - DoH
   - Jitter
   - How-To
   - ATT&CK Mapping
   - Kali
   - Twitter
   - MAPI
   - Site
   - Agent
   - API
   - UI
   - Linux

You can retrieve the entire dataset using the `c2_data` property.

This class provides information about the tools used by actors or groups within the MITRE ATT&CK Frameworks.
Additionally, a `Tool` object allows the user to access additional relationships within the MITRE ATT&CK Frameworks:

* Techniques that the specified tool is used within
* Actor or Group(s) using a specified tool

## Tool Class

```eval_rst
.. autoclass:: pyattck_data_models.tool.Tool
   :members:
   :undoc-members:
   :show-inheritance:
```