import os
import tempfile
import pytest
import random

def get_random_file_or_url():
    if random.choice(['file', 'url']) == 'file':
        return tempfile.NamedTemporaryFile().name
    else:
        return random.choice(['https://letsautomate.it/article/index.xml', 'https://google.com', 'https://github.com/swimlane/pyattck'])

default_config_data = {
    'data_path': os.path.abspath(os.path.expanduser(os.path.expandvars('~/pyattck/data'))),
    'enterprise_attck_json': "https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_enterprise_attck_v1.json",
    'pre_attck_json': "https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_pre_attck_v1.json",
    'mobile_attck_json': "https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_mobile_attck_v1.json",
    'ics_attck_json': "https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_ics_attck_v1.json",
    'nist_controls_json': "https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-control-framework-mappings/main/frameworks/attack_10_1/nist800_53_r4/stix/nist800-53-r4-controls.json",
    'generated_nist_json': "https://swimlane-pyattck.s3.us-west-2.amazonaws.com/attck_to_nist_controls.json",
    'config_file_path': os.path.abspath(os.path.expanduser(os.path.expandvars('~/pyattck/config.yml'))),\
    'save_config': False,
    'use_config': False,
    'kwargs': {},
    'config_data': {}
}

### Testing Default Configuration Settings

def test_default_configuration_settings_set(attck_configuration):
    assert attck_configuration().use_config == False
    assert attck_configuration().save_config == False
    assert os.path.abspath(os.path.expanduser(os.path.expandvars(attck_configuration().config_file_path))) == os.path.abspath(os.path.expanduser(os.path.expandvars('~/pyattck/config.yml')))
    assert os.path.abspath(os.path.expanduser(os.path.expandvars(attck_configuration().config.data_path))) == os.path.abspath(os.path.expanduser(os.path.expandvars(default_config_data.get('data_path'))))

def test_configuration_save_config(attck_configuration):
    from pyattck import Attck, Configuration
    attck = Attck(save_config=True)
    assert attck.config.save_config == True
    assert isinstance(attck.config.config, Configuration)
    assert os.path.abspath(os.path.expanduser(os.path.expandvars(attck.config.config.data_path))) == attck_configuration().config.data_path

@pytest.mark.parametrize(
    'target_attribute', 
    ['enterprise_attck_json', 'pre_attck_json', 'mobile_attck_json', 'ics_attck_json', 'nist_controls_json', 'generated_nist_json']
)
def test_default_configuration_settings_jsons(attck_configuration, target_attribute):
    from pyattck import Attck
    attck = Attck()
    assert getattr(attck.config.config, target_attribute) == default_config_data[target_attribute]


def test_configuration_data_can_be_file_path_location():
    from pyattck import Configuration, Options

    enterprise_temp_value = get_random_file_or_url()
    pre_attck_temp_value = get_random_file_or_url()
    mobile_temp_value = get_random_file_or_url()
    ics_temp_value = get_random_file_or_url()
    nist_controls_temp_value = get_random_file_or_url()
    generated_nist_temp_value = get_random_file_or_url()

    opt = Options(
        use_config=False,
        save_config=False,
        config=Configuration(
            enterprise_attck_json = enterprise_temp_value,
            pre_attck_json = pre_attck_temp_value,
            mobile_attck_json = mobile_temp_value,
            ics_attck_json = ics_temp_value,
            nist_controls_json = nist_controls_temp_value,
            generated_nist_json = generated_nist_temp_value
        )
    )
   
    assert opt.config.enterprise_attck_json == enterprise_temp_value
    assert opt.config.pre_attck_json == pre_attck_temp_value
    assert opt.config.mobile_attck_json == mobile_temp_value
    assert opt.config.ics_attck_json == ics_temp_value
    assert opt.config.nist_controls_json == nist_controls_temp_value
    assert opt.config.generated_nist_json == generated_nist_temp_value
