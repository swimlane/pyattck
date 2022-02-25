import pytest 


def test_techniques_have_tactics(attck_fixture):
    """
    All MITRE ICS ATT&CK Techniques should have tactics

    Args:
        attck_fixture ([type]): our default MITRE ICS ATT&CK JSON fixture
    """
    for technique in attck_fixture.ics.techniques:
        if technique.tactics:
            assert getattr(technique,'tactics')
    
def test_techniques_have_mitigations(attck_fixture):
    """
    Some MITRE ICS ATT&CK Techniques should have mitigations

    Args:
        attck_fixture ([type]): our default MITRE ICS ATT&CK JSON fixture
    """
    count = 0
    for technique in attck_fixture.ics.techniques:
        if not hasattr(technique, 'mitigations'):
            if technique.mitigations:
                count += 1
    if count >= 1:
        assert True

def test_some_techniques_have_generated_datasets_properties(attck_fixture):
    """
    Some MITRE ICS ATT&CK Techniques should have generated datasets properties

    Args:
        attck_fixture ([type]): our default MITRE ICS ATT&CK JSON fixture
    """
    command_list_count = 0
    commands_count = 0
    queries_count = 0
    datasets_count = 0
    possible_detections_count = 0
    
    for technique in attck_fixture.ics.techniques:
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


def test_some_techniques_have_compliance_controls(attck_fixture):
    """
    Some MITRE ICS ATT&CK Techniques should have compliance controls

    Args:
        attck_fixture ([type]): our default MITRE ICS ATT&CK JSON fixture
    """
    count = 0
    for technique in attck_fixture.ics.techniques:
        if technique.controls:
            for control in technique.controls:
                if control:
                    count += 1
    if count >= 1:
        assert True

def test_techniques_have_malwares(attck_fixture):
    """
    Some MITRE ICS ATT&CK Techniques should have malwares

    Args:
        attck_fixture ([type]): our default MITRE ICS ATT&CK JSON fixture
    """
    count = 0
    for technique in attck_fixture.ics.techniques:
        if not hasattr(technique, 'malwares'):
            if technique.malwares:
                count += 1
    if count >= 1:
        assert True
