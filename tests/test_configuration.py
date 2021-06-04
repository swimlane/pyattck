import os
import tempfile
import yaml
import pytest
import random

def get_random_file_or_url():
    if random.choice(['file', 'url']) == 'file':
        return tempfile.NamedTemporaryFile().name
    else:
        return random.choice(['https://letsautomate.it/article/index.xml', 'https://google.com', 'https://github.com/swimlane/pyattck'])

default_config_data = {
    'data_path': os.path.abspath(os.path.expanduser(os.path.expandvars('~/pyattck/data'))),
    'enterprise_attck_json': "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
    'pre_attck_json': "https://raw.githubusercontent.com/mitre/cti/master/pre-attack/pre-attack.json",
    'mobile_attck_json': "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json",
    'nist_controls_json': "https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-control-framework-mappings/master/frameworks/nist800-53-r4/stix/nist800-53-r4-controls.json",
    'generated_attck_json': "https://github.com/swimlane/pyattck/blob/master/generated_attck_data.json?raw=True",
    'generated_nist_json': "https://github.com/swimlane/pyattck/blob/master/attck_to_nist_controls.json?raw=True"
}

### Testing Default Configuration Settings

def test_default_configuration_settings_set(attck_configuration):
    assert attck_configuration.use_config == False
    assert attck_configuration.save_config == False
    assert attck_configuration.config_file_path == os.path.abspath(os.path.expanduser(os.path.expandvars('~/pyattck/config.yml')))
    assert attck_configuration.data_path == os.path.abspath(os.path.expanduser(os.path.expandvars(default_config_data.get('data_path'))))

@pytest.mark.parametrize(
    'target_attribute', 
    ['enterprise_attck_json', 'pre_attck_json', 'mobile_attck_json', 'nist_controls_json', 'generated_attck_json', 'generated_nist_json']
)
def test_default_configuration_settings_jsons(attck_configuration, target_attribute):
    assert getattr(attck_configuration, target_attribute) == default_config_data[target_attribute]


def test_configuration_data_can_be_file_path_location(attck_configuration):
    attck_configuration.use_config = False
    attck_configuration.save_config = False

    enterprise_temp_value = get_random_file_or_url()
    pre_attck_temp_value = get_random_file_or_url()
    mobile_temp_value = get_random_file_or_url()
    nist_controls_temp_value = get_random_file_or_url()
    generated_attck_temp_value = get_random_file_or_url()
    generated_nist_temp_value = get_random_file_or_url()
    attck_configuration.enterprise_attck_json = enterprise_temp_value
    attck_configuration.pre_attck_json = pre_attck_temp_value
    attck_configuration.mobile_attck_json = mobile_temp_value
    attck_configuration.nist_controls_json = nist_controls_temp_value
    attck_configuration.generated_nist_json = generated_nist_temp_value
    attck_configuration.generated_attck_json = generated_attck_temp_value

    config_data = attck_configuration.config_data

    assert attck_configuration.enterprise_attck_json == enterprise_temp_value
    assert config_data['enterprise_attck_json'] == enterprise_temp_value
    attck_configuration.enterprise_attck_json = default_config_data['enterprise_attck_json']

    assert attck_configuration.pre_attck_json == pre_attck_temp_value
    assert config_data['pre_attck_json'] == pre_attck_temp_value
    attck_configuration.pre_attck_json = default_config_data['pre_attck_json']

    assert attck_configuration.mobile_attck_json == mobile_temp_value
    assert config_data['mobile_attck_json'] == mobile_temp_value
    attck_configuration.mobile_attck_json = default_config_data['mobile_attck_json']

    assert attck_configuration.nist_controls_json == nist_controls_temp_value
    assert config_data['nist_controls_json'] == nist_controls_temp_value
    attck_configuration.nist_controls_json = default_config_data['nist_controls_json']

    assert attck_configuration.generated_attck_json == generated_attck_temp_value
    assert config_data['generated_attck_json'] == generated_attck_temp_value
    attck_configuration.generated_attck_json = default_config_data['generated_attck_json']

    assert attck_configuration.generated_nist_json == generated_nist_temp_value
    assert config_data['generated_nist_json'] == generated_nist_temp_value
    attck_configuration.generated_nist_json = default_config_data['generated_nist_json']

    attck_configuration.save_config = True
    attck_configuration.config_data


def test_configuration_settings_use_config_sets_config_values(attck_configuration):
    attck_configuration.use_config = True
    assert attck_configuration.use_config == True
    with tempfile.NamedTemporaryFile('w+') as f:
        yaml.dump(default_config_data, f)
        attck_configuration.config_file_path = f.name
        assert attck_configuration.config_data
        assert isinstance(attck_configuration.config_data, dict)
        assert attck_configuration.data_path == os.path.abspath(os.path.expanduser(os.path.expandvars(default_config_data.get('data_path'))))
        assert attck_configuration.enterprise_attck_json == default_config_data['enterprise_attck_json']
        assert attck_configuration.pre_attck_json == default_config_data['pre_attck_json']
        assert attck_configuration.mobile_attck_json == default_config_data['mobile_attck_json']
        assert attck_configuration.nist_controls_json == default_config_data['nist_controls_json']
        assert attck_configuration.generated_attck_json == default_config_data['generated_attck_json']
        assert attck_configuration.generated_nist_json == default_config_data['generated_nist_json']

def test_use_config_defaults_to_set_config_data(attck_configuration):
    attck_configuration.use_config = True
    assert attck_configuration.use_config == True
    with tempfile.NamedTemporaryFile() as f:
        f.write(b'')
        attck_configuration.config_file_path = f.name
        assert attck_configuration.config_data
        assert isinstance(attck_configuration.config_data, dict)
        assert attck_configuration.config_data.get('data_path')
        assert attck_configuration.config_data.get('enterprise_attck_json')
        assert attck_configuration.config_data.get('pre_attck_json')
        assert attck_configuration.config_data.get('mobile_attck_json')
        assert attck_configuration.config_data.get('nist_controls_json')
        assert attck_configuration.config_data.get('generated_attck_json')
        assert attck_configuration.config_data.get('generated_nist_json')

def test_configuration_settings_save_config(attck_configuration):
    attck_configuration.enterprise_attck_json = default_config_data['enterprise_attck_json']
    attck_configuration.pre_attck_json = default_config_data['pre_attck_json']
    attck_configuration.mobile_attck_json = default_config_data['mobile_attck_json']
    attck_configuration.nist_controls_json = default_config_data['nist_controls_json']
    attck_configuration.generated_attck_json = default_config_data['generated_attck_json']
    attck_configuration.generated_nist_json = default_config_data['generated_nist_json']
    attck_configuration.save_config = False
    temp_value = tempfile.NamedTemporaryFile(suffix='.yml').name
    attck_configuration.config_file_path = temp_value
    assert attck_configuration.config_file_path == temp_value
    temp_dir = tempfile.TemporaryDirectory().name
    attck_configuration.data_path = temp_dir
    assert attck_configuration.data_path == temp_dir

