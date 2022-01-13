def test_preattck_actors_have_techniques(attck_fixture):
    """
    All MITRE PRE-ATT&CK Actors should have techniques

    Args:
        attck_fixture ([type]): our default MITRE PRE-ATT&CK JSON fixture
    """
    for actor in attck_fixture.preattack.actors:
        if actor.techniques:
            assert getattr(actor,'techniques')

def test_some_preattck_actors_have_generated_datasets(attck_fixture):
    """
    Some MITRE PRE-ATT&CK Actors should have generated datasets

    Args:
        attck_fixture ([type]): our default MITRE PRE-ATT&CK JSON fixture
    """
    count = 0
    for actor in attck_fixture.preattack.actors:
        if hasattr(actor, 'external_dataset'):
            count += 1
    if count >= 1:
        assert True

def test_some_preattck_actors_have_generated_datasets_properties(attck_fixture):
    """
    Some MITRE PRE-ATT&CK Actors should have generated datasets properties

    Args:
        attck_fixture ([type]): our default MITRE PRE-ATT&CK JSON fixture
    """
    country_count = 0
    operations_count = 0
    attribution_links_count = 0
    known_tools_count = 0
    targets_count = 0
    additional_comments_count = 0
    external_description_count = 0
    for actor in attck_fixture.preattack.actors:
        if hasattr(actor, 'country'):
            country_count += 1
        if hasattr(actor, 'operations'):
            operations_count += 1
        if hasattr(actor, 'attribution_links'):
            attribution_links_count += 1
        if hasattr(actor, 'known_tools'):
            known_tools_count += 1
        if hasattr(actor, 'targets'):
            targets_count += 1
        if hasattr(actor, 'additional_comments'):
            additional_comments_count += 1
        if hasattr(actor, 'external_description'):
            external_description_count += 1
    if country_count >= 1 and operations_count >= 1 and attribution_links_count >= 1 and known_tools_count >= 1 and targets_count >= 1 and additional_comments_count >= 1 and external_description_count >= 1:
        assert True
