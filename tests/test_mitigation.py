import pytest


@pytest.mark.parametrize(
    'target_attribute', 
    ['enterprise', 'mobile', 'ics']
)
def test_mitigation_have_techniques(attck_fixture, target_attribute):
    """
    Some MITRE ATT&CK Mitigation should have Techniques

    Args:
        attck_fixture ([type]): our default MITRE ATT&CK JSON fixture
    """
    for mitigation in getattr(attck_fixture, target_attribute).mitigations:
        if mitigation.techniques:
            assert getattr(mitigation,'techniques')
