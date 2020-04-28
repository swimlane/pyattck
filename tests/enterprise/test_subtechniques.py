import pytest 


def test_subtechniques_have_tactics(attck_fixture_subtechniques):
    """All Mitre ATT&CK Techniques should have tactics
    
    Args:
        attck_fixture ([type]): our default Mitre ATT&CK JSON fixture
    """
    for technique in attck_fixture_subtechniques.enterprise.techniques:
        if technique.subtechniques:
            for subtechnique in technique.subtechniques:
                assert getattr(subtechnique,'tactics')