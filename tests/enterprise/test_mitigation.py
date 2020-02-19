def test_mitigation_have_techniques(attck_fixture):
    """Some Mitre ATT&CK Mitigation should have Techniques
    
    Args:
        attck_fixture ([type]): our default Mitre ATT&CK JSON fixture
    """
    for mitigation in attck_fixture.enterprise.mitigations:
        if mitigation.techniques:
            assert getattr(mitigation,'techniques')
