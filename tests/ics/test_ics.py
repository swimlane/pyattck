import pytest
import os


@pytest.mark.parametrize(
    'target_attribute', 
    ['techniques', 'tactics', 'mitigations', 'malwares', 'controls']
)
def test_attck_attribute_is_list(target_attribute):
    from pyattck import Attck
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'fixtures')#, 'generated_attck_data' + '.json')
    attck = Attck(data_path=path)
    ics = getattr(attck, 'ics')
    assert isinstance(
        getattr(ics, target_attribute),
        list
    )

@pytest.mark.parametrize(
    'target_attribute', 
    ['techniques', 'tactics', 'mitigations', 'malwares', 'controls']
)
@pytest.mark.parametrize(
    'target_properties',
    ['id','name','description','reference','created','modified','stix','type']
)

def test_all_attck_objects_have_standard_properties(target_attribute,target_properties):
    from pyattck import Attck
    path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'fixtures')#, 'generated_attck_data' + '.json')
    attck = Attck(data_path=path)
    ics = getattr(attck, 'ics')
    return_list = []
    for attribute in getattr(ics,target_attribute):
        if hasattr(attribute, target_properties):
            return_list.append(getattr(attribute,target_properties))
    if len(return_list) >= 1:
        assert True
