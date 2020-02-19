
def test_actors_have_tools(attck_fixture):
    """All Mitre ATT&CK Techniques should have tactics
    
    Args:
        attck_fixture ([type]): our default Mitre ATT&CK JSON fixture
    """
    for actor in attck_fixture.enterprise.actors:
        if actor.tools:
            assert getattr(actor,'tools')

def test_actors_have_malwares(attck_fixture):
    """All Mitre ATT&CK Techniques should have tactics
    
    Args:
        attck_fixture ([type]): our default Mitre ATT&CK JSON fixture
    """
    for actor in attck_fixture.enterprise.actors:
        if actor.malwares:
            assert getattr(actor,'malwares')

def test_actors_have_techniques(attck_fixture):
    """All Mitre ATT&CK Techniques should have techniques
    
    Args:
        attck_fixture ([type]): our default Mitre ATT&CK JSON fixture
    """
    for actor in attck_fixture.enterprise.actors:
        if actor.techniques:
            assert getattr(actor,'techniques')


def test_some_actors_have_generated_datasets(attck_fixture):
    """All Mitre ATT&CK Techniques should have techniques
    
    Args:
        attck_fixture ([type]): our default Mitre ATT&CK JSON fixture
    """
    count = 0
    for actor in attck_fixture.enterprise.actors:
        if hasattr(actor, 'external_dataset'):
            count += 1
    if count >= 1:
        assert True

def test_some_actors_have_generated_datasets_properties(attck_fixture):
    """All Mitre ATT&CK Techniques should have techniques
    
    Args:
        attck_fixture ([type]): our default Mitre ATT&CK JSON fixture
    """
    country_count = 0
    operations_count = 0
    attribution_links_count = 0
    known_tools_count = 0
    targets_count = 0
    additional_comments_count = 0
    external_description_count = 0
    for actor in attck_fixture.enterprise.actors:
        if hasattr(actor, 'country'):
            country_count += 1
        if hasattr(actor, 'operations'):
            operations_count += 1
        if hasattr(actor, 'attribution_links'):
            attribution_links_count += 1
        if hasattr(actor, 'known_tools'):
            known_tools_count += 1
        if hasattr(actor, 'targets'):
            targets_count += 1
        if hasattr(actor, 'additional_comments'):
            additional_comments_count += 1
        if hasattr(actor, 'external_description'):
            external_description_count += 1

    if country_count >= 1 and operations_count >= 1 and attribution_links_count >= 1 and known_tools_count >= 1 and targets_count >= 1 and additional_comments_count >= 1 and external_description_count >= 1:
        assert True
   
def test_actors_has_ascii_logo(attck_fixture):
    """All Mitre ATT&CK Techniques should have techniques
    
    Args:
        attck_fixture ([type]): our default Mitre ATT&CK JSON fixture
    """
    count = 0
    logo_count = 0
    for actor in attck_fixture.enterprise.actors:
        count += 1
        if hasattr(actor, 'ascii_logo'):
            logo_count += 1
        
    if count == logo_count:
        assert True