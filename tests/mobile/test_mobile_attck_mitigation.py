def test_mobile_attck_mitigation_have_techniques(attck_fixture):
    """
    Some MITRE Mobile ATT&CK Mitigation should have Techniques

    Args:
        attck_fixture ([type]): our default MITRE Mobile ATT&CK JSON fixture
    """
    for mitigation in attck_fixture.mobile.mitigations:
        if mitigation.techniques:
            assert getattr(mitigation,'techniques')
