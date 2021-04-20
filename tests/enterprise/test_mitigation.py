def test_mitigation_have_techniques(attck_fixture):
    """
    Some MITRE Enterprise ATT&CK Mitigation should have Techniques

    Args:
        attck_fixture ([type]): our default MITRE Enterprise ATT&CK JSON fixture
    """
    for mitigation in attck_fixture.enterprise.mitigations:
        if mitigation.techniques:
            assert getattr(mitigation,'techniques')
