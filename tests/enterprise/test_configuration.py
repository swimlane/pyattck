import pytest
import os
import yaml
from os.path import expanduser


def test_config_in_default_location():
    from pyattck import Attck
    Attck()

    assert os.path.isfile(os.path.join(expanduser('~'), 'pyattck', 'config' + '.yml'))

def test_config_attck_json_path_default_value():
    from pyattck import Attck
    Attck()
    
    config_path = os.path.abspath(os.path.join(expanduser('~'), 'pyattck', 'config' + '.yml'))
    config = None
    with open(config_path) as f:
        config = yaml.load(f, Loader=yaml.FullLoader)
    assert os.path.join(config.get('data_path'), config['enterprise'].get('filename')) == os.path.join(config.get('data_path'), 'enterprise_attck' + '.json')

def test_config_attck_json_path_provided_value(tmpdir):
    from pyattck import Attck
    config_path = os.path.abspath(os.path.join(expanduser('~'), 'pyattck', 'config' + '.yml'))
    path = tmpdir.mkdir('pyattck')
    Attck(data_path=str(path))
    
    config = None
    with open(config_path) as f:
        config = yaml.load(f, Loader=yaml.FullLoader)
    assert os.path.join(config.get('data_path'), config['enterprise'].get('filename')) == os.path.join(config.get('data_path'), 'enterprise_attck' + '.json')

def test_config_dataset_json_path_default_value():
    from pyattck import Attck
    Attck()
    
    config = None
    with open(os.path.abspath(os.path.join(expanduser('~'), 'pyattck', 'config' + '.yml'))) as f:
        config = yaml.load(f, Loader=yaml.FullLoader)
    assert os.path.join(config.get('data_path'), config['generated_data'].get('filename')) == os.path.abspath(os.path.join(expanduser('~'), 'pyattck', 'enterprise_attck_dataset' + '.json'))


def test_config_alternate_location(tmpdir):
    config_path = str(tmpdir.mkdir('pyattck').join('config.yml'))
    from pyattck import Attck
    Attck(config_file_path=config_path)
    
    assert len(tmpdir.listdir()) == 1