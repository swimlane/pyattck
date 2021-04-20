def test_preattck_tactics_have_techniques(attck_fixture):
    """
    All MITRE PRE-ATT&CK Tactics should have Techniques

    Args:
        attck_fixture ([type]): our default MITRE PRE-ATT&CK JSON fixture
    """
    for tactic in attck_fixture.preattack.tactics:
        assert getattr(tactic,'techniques')
