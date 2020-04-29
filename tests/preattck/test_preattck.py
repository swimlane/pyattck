import pytest
import os
import yaml
from os.path import expanduser


@pytest.mark.parametrize(
    'target_attribute', 
    ['techniques', 'tactics', 'actors']
)
def test_preattck_attck_attribute_is_list(target_attribute):
    from pyattck import Attck
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'fixtures', 'generated_attck_data' + '.json')
    attck = Attck()
    preattack = getattr(attck, 'preattack')
    assert isinstance(
        getattr(preattack, target_attribute),
        list
    )

@pytest.mark.parametrize(
    'target_attribute', 
    ['techniques', 'tactics', 'actors']
)
@pytest.mark.parametrize(
    'target_properties',
    ['id','name','description','created','modified','stix','type']
)

def test_all_preattck_attck_objects_have_standard_properties(target_attribute,target_properties):
    from pyattck import Attck
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'fixtures', 'generated_attck_data' + '.json')
    attck = Attck()
    preattack = getattr(attck, 'preattack')
    for attribute in getattr(preattack,target_attribute):
        assert getattr(attribute,target_properties)
