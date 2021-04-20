def test_mobile_attck_tactics_have_techniques(attck_fixture):
    """
    All MITRE Mobile ATT&CK Techniques should have tactics

    Args:
        attck_fixture ([type]): our default MITRE Mobile ATT&CK JSON fixture
    """
    for tactic in attck_fixture.mobile.tactics:
        assert getattr(tactic,'techniques')
