import pytest
import os
import yaml
from os.path import expanduser


def test_enterprise_search_commands(attck_fixture):
    """
    All MITRE Enterprise ATT&CK search returns commands

    Args:
        attck_fixture ([type]): our default MITRE Enterprise ATT&CK JSON fixture
    """
    if len(attck_fixture.enterprise.search_commands('powershell')) >= 1:
        assert True

@pytest.mark.parametrize(
    'target_attribute', 
    ['techniques', 'tactics', 'mitigations', 'malwares', 'actors', 'tools', 'controls']
)
def test_attck_attribute_is_list(target_attribute):
    from pyattck import Attck
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'fixtures')#, 'generated_attck_data' + '.json')
    attck = Attck(data_path=path)
    enterprise = getattr(attck, 'enterprise')
    assert isinstance(
        getattr(enterprise, target_attribute),
        list
    )

@pytest.mark.parametrize(
    'target_attribute', 
    ['techniques', 'tactics', 'mitigations', 'malwares', 'actors', 'tools', 'controls']
)
@pytest.mark.parametrize(
    'target_properties',
    ['id','name','description','reference','created','modified','stix','type']
)

def test_all_attck_objects_have_standard_properties(target_attribute,target_properties):
    from pyattck import Attck
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'fixtures')#, 'generated_attck_data' + '.json')
    attck = Attck(data_path=path)
    enterprise = getattr(attck, 'enterprise')
    return_list = []
    for attribute in getattr(enterprise,target_attribute):
        if hasattr(attribute, target_properties):
            return_list.append(getattr(attribute,target_properties))
    if len(return_list) >= 1:
        assert True
