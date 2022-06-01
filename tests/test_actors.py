import pytest


@pytest.mark.parametrize("target_attribute", ["enterprise", "mobile", "preattack"])
def test_actors_have_tools(attck_fixture, target_attribute):
    """
    All MITRE ATT&CK Frameworks Actors should have tools

    Args:
        attck_fixture ([type]): our default MITRE ATT&CK JSON fixture
    """
    for actor in getattr(attck_fixture, target_attribute).actors:
        if actor.tools:
            assert getattr(actor, "tools")


@pytest.mark.parametrize("target_attribute", ["enterprise", "mobile"])
def test_actors_have_malwares(attck_fixture, target_attribute):
    """
    All MITRE ATT&CK Framework Actors should have malwares

    Args:
        attck_fixture ([type]): our default MITRE ATT&CK JSON fixture
    """
    for actor in getattr(attck_fixture, target_attribute).actors:
        if actor.malwares:
            assert getattr(actor, "malwares")


@pytest.mark.parametrize("target_attribute", ["enterprise", "mobile", "preattack"])
def test_actors_have_techniques(attck_fixture, target_attribute):
    """
    All MITRE ATT&CK Actors should have techniques

    Args:
        attck_fixture ([type]): our default MITRE ATT&CK JSON fixture
    """
    for actor in getattr(attck_fixture, target_attribute).actors:
        if actor.techniques:
            assert getattr(actor, "techniques")


@pytest.mark.parametrize("target_attribute", ["enterprise", "mobile", "preattack"])
def test_some_actors_have_generated_datasets_properties(attck_fixture, target_attribute):
    """
    Some MITRE Enterprise ATT&CK Actors should have generated datasets properties

    Args:
        attck_fixture ([type]): our default MITRE Enterprise ATT&CK JSON fixture
    """
    country_count = 0
    operations_count = 0
    attribution_links_count = 0
    known_tools_count = 0
    targets_count = 0
    additional_comments_count = 0
    external_description_count = 0
    for actor in getattr(attck_fixture, target_attribute).actors:
        if hasattr(actor, "country"):
            country_count += 1
        if hasattr(actor, "operations"):
            operations_count += 1
        if hasattr(actor, "attribution_links"):
            attribution_links_count += 1
        if hasattr(actor, "known_tools"):
            known_tools_count += 1
        if hasattr(actor, "targets"):
            targets_count += 1
        if hasattr(actor, "additional_comments"):
            additional_comments_count += 1
        if hasattr(actor, "external_description"):
            external_description_count += 1

    if (
        country_count >= 1
        and operations_count >= 1
        and attribution_links_count >= 1
        and known_tools_count >= 1
        and targets_count >= 1
        and additional_comments_count >= 1
        and external_description_count >= 1
    ):
        assert True
