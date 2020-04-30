
def test_mobile_attck_tools_have_techniques(attck_fixture):
    """All MITRE Mobile ATT&CK tools should have techniques
    
    Args:
        attck_fixture ([type]): our default MITRE Mobile ATT&CK JSON fixture
    """
    for tool in attck_fixture.mobile.tools:
        if tool.techniques:
            assert getattr(tool,'techniques')

def test_mobile_attck_tools_have_actors(attck_fixture):
    """All MITRE Mobile ATT&CK Tools should have Actors
    
    Args:
        attck_fixture ([type]): our default MITRE Mobile ATT&CK JSON fixture
    """
    for tool in attck_fixture.mobile.tools:
        if tool.actors:
            assert getattr(tool,'actors')



def test_mobile_attck_some_tools_have_c2_data(attck_fixture):
    """All MITRE Mobile ATT&CK Tools should have c2 Matrix Data
    
    Args:
        attck_fixture ([type]): our default MITRE Mobile ATT&CK JSON fixture
    """
    count = 0
    for tool in attck_fixture.mobile.tools:
        if hasattr(tool, 'c2_data'):
            count += 1
    if count >= 1:
        assert True

def test_mobile_attck_some_tools_have_generated_datasets(attck_fixture):
    """All MITRE Mobile ATT&CK Tools should have generated datasets
    
    Args:
        attck_fixture ([type]): our default MITRE Mobile ATT&CK JSON fixture
    """
    count = 0
    for tool in attck_fixture.mobile.tools:
        if hasattr(tool, 'external_dataset'):
            count += 1
    if count >= 1:
        assert True

def test_mobile_attck_some_tools_have_generated_datasets_properties(attck_fixture):
    """All MITRE Mobile ATT&CK Tools should have generated datasets properties
    
    Args:
        attck_fixture ([type]): our default MITRE Mobile ATT&CK JSON fixture
    """
    additional_names_count = 0
    attribution_links_count = 0
    additional_comments_count = 0
    family_count = 0
    
    for tool in attck_fixture.mobile.tools:
        if hasattr(tool, 'additional_names'):
            additional_names_count += 1
        if hasattr(tool, 'additional_comments'):
            additional_comments_count += 1
        if hasattr(tool, 'attribution_links'):
            attribution_links_count += 1
        if hasattr(tool, 'family'):
            family_count += 1

    if additional_names_count >= 1 and additional_comments_count >= 1 and attribution_links_count >= 1 and family_count >= 1:
        assert True