
def test_tactics_have_techniques(attck_fixture):
    """All MITRE Enterprise ATT&CK Tactics should have Techniques
    
    Args:
        attck_fixture ([type]): our default MITRE Enterprise ATT&CK JSON fixture
    """
    for tactic in attck_fixture.enterprise.tactics:
        assert getattr(tactic,'techniques')
