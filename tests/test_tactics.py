import pytest


@pytest.mark.parametrize(
    'target_attribute', 
    ['enterprise', 'mobile', 'preattack', 'ics']
)
def test_tactics_have_techniques(attck_fixture, target_attribute):
    """
    All MITRE ATT&CK Tactics should have Techniques

    Args:
        attck_fixture ([type]): our default MITRE ATT&CK JSON fixture
    """
    for tactic in getattr(attck_fixture, target_attribute).tactics:
        assert getattr(tactic,'techniques')
