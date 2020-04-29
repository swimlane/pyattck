
def test_preattck_tactics_have_techniques(attck_fixture):
    """All Mitre PRE-ATT&CK Techniques should have tactics
    
    Args:
        attck_fixture ([type]): our default Mitre PRE-ATT&CK JSON fixture
    """
    for tactic in attck_fixture.preattack.tactics:
        assert getattr(tactic,'techniques')
