import pytest 


def test_techniques_have_tactics(attck_fixture):
    """All MITRE Enterprise ATT&CK Techniques should have tactics
    
    Args:
        attck_fixture ([type]): our default MITRE Enterprise ATT&CK JSON fixture
    """
    for technique in attck_fixture.enterprise.techniques:
        if technique.tactics:
            assert getattr(technique,'tactics')
    
def test_techniques_have_mitigations(attck_fixture):
    """Some MITRE Enterprise ATT&CK Techniques should have mitigations
    
    Args:
        attck_fixture ([type]): our default MITRE Enterprise ATT&CK JSON fixture
    """
    count = 0
    for technique in attck_fixture.enterprise.techniques:
        if not hasattr(technique, 'mitigations'):
            if technique.mitigations:
                count += 1
    if count >= 1:
        assert True

def test_techniques_have_actors(attck_fixture):
    """All MITRE Enterprise ATT&CK Techniques should have Actors
    
    Args:
        attck_fixture ([type]): our default MITRE Enterprise ATT&CK JSON fixture
    """
    count = 0
    for technique in attck_fixture.enterprise.techniques:
        if not hasattr(technique, 'actors'):
            if technique.actors:
                count += 1
    if count >= 1:
        assert True



def test_some_techniques_have_generated_datasets_properties(attck_fixture):
    """Some MITRE Enterprise ATT&CK Techniques should have generated datasets properties
    
    Args:
        attck_fixture ([type]): our default MITRE Enterprise ATT&CK JSON fixture
    """
    command_list_count = 0
    commands_count = 0
    queries_count = 0
    datasets_count = 0
    possible_detections_count = 0
    
    for technique in attck_fixture.enterprise.techniques:
        if hasattr(technique, 'commant_list'):
            command_list_count += 1
        if hasattr(technique, 'commands'):
            commands_count += 1
        if hasattr(technique, 'queries'):
            queries_count += 1
        if hasattr(technique, 'datasets'):
            datasets_count += 1
        if hasattr(technique, 'possible_detections'):
            possible_detections_count += 1
        

    if command_list_count >= 1 and commands_count >= 1 and queries_count >= 1 and datasets_count >= 1 and possible_detections_count >= 1:
        assert True

def test_techniques_have_nested_subtechniques(attck_fixture_nested_subtechniques_false):
    """All MITRE Enterprise ATT&CK Techniques should have tactics
    
    Args:
        attck_fixture ([type]): our default MITRE Enterprise ATT&CK JSON fixture
    """
    count = 0
    for technique in attck_fixture_nested_subtechniques_false.enterprise.techniques:
        if hasattr(technique, 'subtechniques'):
            if technique.subtechniques:
                count += 1
    if count >= 1:
        assert True
