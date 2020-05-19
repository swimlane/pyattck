import pytest
import os
import yaml
from os.path import expanduser


@pytest.mark.parametrize(
    'target_attribute', 
    ['techniques', 'tactics', 'actors', 'mitigations', 'tools', 'malwares']
)
def test_mobile_attck_attck_attribute_is_list(target_attribute):
    from pyattck import Attck
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'fixtures', 'generated_attck_data' + '.json')
    attck = Attck()
    mobile = getattr(attck, 'mobile')
    assert isinstance(
        getattr(mobile, target_attribute),
        list
    )

@pytest.mark.parametrize(
    'target_attribute', 
    ['techniques', 'tactics', 'actors', 'mitigations', 'tools', 'malwares']
)
@pytest.mark.parametrize(
    'target_properties',
    ['id','name','description','created','modified','stix','type']
)

def test_all_mobile_attck_attck_objects_have_standard_properties(target_attribute,target_properties):
    from pyattck import Attck
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'fixtures', 'generated_attck_data' + '.json')
    attck = Attck()
    mobile = getattr(attck, 'mobile')
    return_list = []
    for attribute in getattr(mobile,target_attribute):
        if hasattr(attribute, target_properties):
            return_list.append(getattr(attribute,target_properties))
    if len(return_list) >= 1:
        assert True
