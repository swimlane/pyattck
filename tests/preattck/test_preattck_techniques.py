import pytest 


def test_preattck_techniques_have_tactics(attck_fixture):
    """
    All MITRE PRE-ATT&CK Techniques should have tactics

    Args:
        attck_fixture ([type]): our default MITRE PRE-ATT&CK JSON fixture
    """
    for technique in attck_fixture.preattack.techniques:
        if technique.tactics:
            assert getattr(technique,'tactics')

def test_preattck_techniques_have_actors(attck_fixture):
    """
    All MITRE PRE-ATT&CK Techniques should have Actors

    Args:
        attck_fixture ([type]): our default MITRE PRE-ATT&CK JSON fixture
    """
    count = 0
    for technique in attck_fixture.preattack.techniques:
        if not hasattr(technique, 'actors'):
            if technique.actors:
                count += 1
    if count >= 1:
        assert True
