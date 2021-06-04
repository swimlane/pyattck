def test_controls_have_techniques(attck_fixture):
    """
    All MITRE Enterprise ATT&CK Malware should have Actors

    Args:
        attck_fixture ([type]): our default MITRE Enterprise ATT&CK JSON fixture
    """
    for control in attck_fixture.enterprise.controls:
        if control.techniques:
            assert getattr(control,'techniques')
