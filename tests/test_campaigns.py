import pytest


@pytest.mark.parametrize("target_attribute", ["enterprise"])
def test_campaigns(attck_fixture, target_attribute):
    """
    All MITRE ATT&CK Frameworks Campaigns should have tools

    Args:
        attck_fixture ([type]): our default MITRE ATT&CK JSON fixture
    """
    campaign_list = set()
    for campaign in getattr(attck_fixture, target_attribute).campaigns:
        if campaign.name not in campaign_list:
            campaign_list.add(campaign.name)
        else:
            assert False
    assert True


@pytest.mark.parametrize("target_attribute", ["enterprise"])
def test_campaigns_have_malwares(attck_fixture, target_attribute):
    """
    All MITRE ATT&CK Framework Campaigns should have malwares

    Args:
        attck_fixture ([type]): our default MITRE ATT&CK JSON fixture
    """
    for campaign in getattr(attck_fixture, target_attribute).campaigns:
        if campaign.malwares:
            assert getattr(campaign, "malwares")


@pytest.mark.parametrize("target_attribute", ["enterprise"])
def test_campaigns_have_techniques(attck_fixture, target_attribute):
    """
    All MITRE ATT&CK Campaigns should have techniques

    Args:
        attck_fixture ([type]): our default MITRE ATT&CK JSON fixture
    """
    for campaign in getattr(attck_fixture, target_attribute).campaigns:
        if campaign.techniques:
            assert getattr(campaign, "techniques")
