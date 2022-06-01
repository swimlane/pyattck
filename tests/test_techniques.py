import pytest


@pytest.mark.parametrize("target_attribute", ["enterprise", "mobile", "preattack", "ics"])
def test_techniques_have_tactics(attck_fixture, target_attribute):
    """
    All MITRE ATT&CK Techniques should have tactics

    Args:
        attck_fixture ([type]): our default MITRE ATT&CK JSON fixture
    """
    for technique in getattr(attck_fixture, target_attribute).techniques:
        if technique.tactics:
            assert getattr(technique, "tactics")


@pytest.mark.parametrize("target_attribute", ["enterprise", "mobile", "ics"])
def test_techniques_have_mitigations(attck_fixture, target_attribute):
    """
    Some MITRE  ATT&CK Techniques should have mitigations

    Args:
        attck_fixture ([type]): our default MITRE  ATT&CK JSON fixture
    """
    count = 0
    for technique in getattr(attck_fixture, target_attribute).techniques:
        if not hasattr(technique, "mitigations"):
            if technique.mitigations:
                count += 1
    if count >= 1:
        assert True


@pytest.mark.parametrize("target_attribute", ["enterprise", "mobile", "preattack"])
def test_techniques_have_actors(attck_fixture, target_attribute):
    """
    All MITRE  ATT&CK Techniques should have Actors

    Args:
        attck_fixture ([type]): our default MITRE  ATT&CK JSON fixture
    """
    count = 0
    for technique in getattr(attck_fixture, target_attribute).techniques:
        if not hasattr(technique, "actors"):
            if technique.actors:
                count += 1
    if count >= 1:
        assert True


@pytest.mark.parametrize("target_attribute", ["enterprise", "mobile", "preattack", "ics"])
def test_some_techniques_have_generated_datasets_properties(attck_fixture, target_attribute):
    """
    Some MITRE  ATT&CK Techniques should have generated datasets properties

    Args:
        attck_fixture ([type]): our default MITRE  ATT&CK JSON fixture
    """
    command_list_count = 0
    commands_count = 0
    queries_count = 0
    datasets_count = 0
    possible_detections_count = 0

    for technique in getattr(attck_fixture, target_attribute).techniques:
        if hasattr(technique, "command_list"):
            command_list_count += 1
        if hasattr(technique, "commands"):
            commands_count += 1
        if hasattr(technique, "queries"):
            queries_count += 1
        if hasattr(technique, "datasets"):
            datasets_count += 1
        if hasattr(technique, "possible_detections"):
            possible_detections_count += 1
    if (
        command_list_count >= 1
        and commands_count >= 1
        and queries_count >= 1
        and datasets_count >= 1
        and possible_detections_count >= 1
    ):
        assert True


@pytest.mark.parametrize("target_attribute", ["enterprise", "ics"])
def test_some_techniques_have_compliance_controls(attck_fixture, target_attribute):
    """
    Some MITRE  ATT&CK Techniques should have compliance controls

    Args:
        attck_fixture ([type]): our default MITRE  ATT&CK JSON fixture
    """
    count = 0
    for technique in getattr(attck_fixture, target_attribute).techniques:
        if technique.controls:
            for control in technique.controls:
                if control:
                    count += 1
    if count >= 600:
        assert True


@pytest.mark.parametrize("target_attribute", ["enterprise", "ics", "mobile"])
def test_techniques_have_malwares(attck_fixture, target_attribute):
    """
    Some MITRE  ATT&CK Techniques should have malwares

    Args:
        attck_fixture ([type]): our default MITRE  ATT&CK JSON fixture
    """
    count = 0
    for technique in getattr(attck_fixture, target_attribute).techniques:
        if not hasattr(technique, "malwares"):
            if technique.malwares:
                count += 1
    if count >= 1:
        assert True
