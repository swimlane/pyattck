def test_mitigation_have_techniques(attck_fixture):
    """
    Some MITRE ICS ATT&CK Mitigation should have Techniques

    Args:
        attck_fixture ([type]): our default MITRE ICS ATT&CK JSON fixture
    """
    for mitigation in attck_fixture.ics.mitigations:
        if mitigation.techniques:
            assert getattr(mitigation,'techniques')
