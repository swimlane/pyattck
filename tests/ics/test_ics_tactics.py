def test_tactics_have_techniques(attck_fixture):
    """
    All MITRE ICS ATT&CK Tactics should have Techniques

    Args:
        attck_fixture ([type]): our default MITRE ICS ATT&CK JSON fixture
    """
    for tactic in attck_fixture.ics.tactics:
        assert getattr(tactic,'techniques')
