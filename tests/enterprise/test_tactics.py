
def test_tactics_have_techniques(attck_fixture):
    """All Mitre ATT&CK Techniques should have tactics
    
    Args:
        attck_fixture ([type]): our default Mitre ATT&CK JSON fixture
    """
    for tactic in attck_fixture.enterprise.tactics:
        assert getattr(tactic,'techniques')
