# Configuration

`pyattck` allows you to configure if you store external data and as well as where it is stored. Below shows all available parameters when instantiating the `Attck` object.

```python
from pyattck import Attck

attck = Attck(
    nested_subtechniques=True,
    use_config=False,
    save_config=False,
    config_file_path='~/pyattck/config.yml',
    data_path='~/pyattck/data',
    enterprise_attck_json="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
    pre_attck_json="https://raw.githubusercontent.com/mitre/cti/master/pre-attack/pre-attack.json",
    mobile_attck_json="https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json",
    nist_controls_json="https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-control-framework-mappings/master/frameworks/nist800-53-r4/stix/nist800-53-r4-controls.json",
    generated_attck_json="https://github.com/swimlane/pyattck/blob/master/generated_attck_data.json?raw=True",
    generated_nist_json="https://github.com/swimlane/pyattck/blob/master/attck_to_nist_controls.json?raw=True",
    **kwargs
)
```

By default, `pyattck` will pull the latest external data from their respective locations using HTTP GET requests. `pyattck` currently pulls from the following locations:

* enterprise_attck_json="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
* pre_attck_json="https://raw.githubusercontent.com/mitre/cti/master/pre-attack/pre-attack.json"
* mobile_attck_json="https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json"
* nist_controls_json="https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-control-framework-mappings/master/frameworks/nist800-53-r4/stix/nist800-53-r4-controls.json"
* generated_attck_json="https://github.com/swimlane/pyattck/blob/master/generated_attck_data.json?raw=True"
* generated_nist_json="https://github.com/swimlane/pyattck/blob/master/attck_to_nist_controls.json?raw=True"

You have several options when instantiating the `Attck` object. As of `4.0.0` you can now specify any of the following options:

* use_config - When you specify this argument as `True` pyattck will attempt to retrieve the configuration specified in the `config_file_path` location. If this file is corrupted or cannot be found, we will default to retrieving data from the specified `*_attck_json` locations.
* save_config - When you specify this argument as `True` pyattck will save the configuration file to the specified location set by `config_file_path`. Additionally, we will save all downloaded files to the `data_path` location specified. If you have specified a local path location instead of a download URL for any of the `*_attck_json` parameters we will save this location in our configuration and reference this location going forward. 
* config_file_path - The path to store a configuration file. Default is `~/pyattck/config.yml`
* data_path - The path to store any data files downloaded to the local system. Default is `~/pyattck/data`

### JSON Locations

Additionally, you can specify the location for each individual `*_attck_json` files by passing in either a URI or a local file path. If you have passed in a local file path, we will simply read from this file. 

If you have used the default values or specified an alternative URI location to retrieve these JSON files from, you can additionally pass in `**kwargs` that will be passed along to the `Requests` python package when performing any HTTP requests.

## Configuration Class

```eval_rst
.. autoclass:: pyattck.configuration.Configuration
   :members:
   :undoc-members:
   :show-inheritance:
```