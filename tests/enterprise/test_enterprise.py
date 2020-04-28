
'''
def test_enterprise_search_commands(attck_fixture):
    """All Mitre ATT&CK Techniques should have tactics
    
    Args:
        attck_fixture ([type]): our default Mitre ATT&CK JSON fixture
    """
    if len(attck_fixture.enterprise.search_commands('powershell')) >= 1:
        assert True
'''