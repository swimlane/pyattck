
def test_enterprise_search_commands(attck_fixture):
    """All MITRE Enterprise ATT&CK search returns commands
    
    Args:
        attck_fixture ([type]): our default MITRE Enterprise ATT&CK JSON fixture
    """
    if len(attck_fixture.enterprise.search_commands('powershell')) >= 1:
        assert True
