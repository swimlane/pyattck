# Configuration

This documentation provides details about configuration options within the `pyattck` package.


### Specifying an alternate storage location

You can also specify an alternate location of different file objects.

You can specify the path of an `attck_json` as well as `preattck_json` and `dataset_json` when instantiating a `Attck` object.

Additionally, you can specify the location of a configuration file using `config_path` which must be a yaml file.

   > Please note that if you use this parameter you will need to reference this path the next time you instantiate an Attck object to use these datasets.

Storing and loading datasets from an alternate location

```python
from pyattck import Attck

attack = Attck(attck_json='/Users/{profile_name}/Desktop/attck_json.json', preattck_json='/Users/{profile_name}/Desktop/preattack.json', dataset_json='/Users/{profile_name}/Desktop/dataset_json.json')
```

Specifying an alternate location for a config.yml file:

```python
from pyattck import Attck

attack = Attck(config_path='/Users/{profile_name}/Desktop/config.yml')
```


## Configuration Class

```eval_rst
.. autoclass:: pyattck.configuration.Configuration
   :members:
   :undoc-members:
   :show-inheritance:
```