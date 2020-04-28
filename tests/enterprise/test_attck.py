import pytest
import os
import yaml
from os.path import expanduser


@pytest.mark.parametrize(
    'target_attribute', 
    ['techniques', 'tactics', 'mitigations', 'malwares', 'actors', 'tools']
)
def test_attck_attribute_is_list(target_attribute):
    from pyattck import Attck
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'fixtures', 'generated_attck_data' + '.json')
    attck = Attck(dataset_json=path)
    enterprise = getattr(attck, 'enterprise')
    assert isinstance(
        getattr(enterprise, target_attribute),
        list
    )

@pytest.mark.parametrize(
    'target_attribute', 
    ['techniques', 'tactics', 'mitigations', 'malwares', 'actors', 'tools']
)
def test_attck_attribute_is_list_deprecated(target_attribute):
    from pyattck import Attck
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'fixtures', 'generated_attck_data' + '.json')
    attck = Attck(dataset_json=path)

    assert isinstance(
        getattr(attck, target_attribute),
        list
    )

@pytest.mark.parametrize(
    'target_attribute', 
    ['techniques', 'tactics', 'mitigations', 'malwares', 'actors', 'tools']
)
@pytest.mark.parametrize(
    'target_properties',
    ['id','name','reference','created','modified','stix','type']
)

def test_all_attck_objects_have_standard_properties(target_attribute,target_properties):
    from pyattck import Attck
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'fixtures', 'generated_attck_data' + '.json')
    attck = Attck(dataset_json=path)
    enterprise = getattr(attck, 'enterprise')
    for attribute in getattr(enterprise,target_attribute):
        assert getattr(attribute,target_properties)


@pytest.mark.parametrize(
    'target_attribute', 
    ['techniques', 'tactics', 'mitigations', 'malwares', 'actors', 'tools']
)
@pytest.mark.parametrize(
    'target_properties',
    ['id','name','reference','created','modified','stix','type']
)

def test_all_attck_objects_have_standard_properties_deprecated(target_attribute,target_properties):
    from pyattck import Attck
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'fixtures', 'generated_attck_data' + '.json')
    attck = Attck(dataset_json=path)
    
    for attribute in getattr(attck,target_attribute):
        assert getattr(attribute,target_properties)