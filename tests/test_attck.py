import os
import random
import tempfile

import pytest

default_config_data = {
    "data_path": os.path.abspath(os.path.expanduser(os.path.expandvars("~/pyattck/data"))),
    "enterprise_attck_json": "https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_enterprise_attck_v1.json",
    "pre_attck_json": "https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_pre_attck_v1.json",
    "mobile_attck_json": "https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_mobile_attck_v1.json",
    "ics_attck_json": "https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_ics_attck_v1.json",
    "nist_controls_json": "https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_nist_controls_v1.json",
    "generated_nist_json": "https://swimlane-pyattck.s3.us-west-2.amazonaws.com/attck_to_nist_controls.json",
    "config_file_path": os.path.abspath(os.path.expanduser(os.path.expandvars("~/pyattck/config.yml"))),
}


def get_random_file_or_url():
    if random.choice(["file", "url"]) == "file":
        return tempfile.NamedTemporaryFile().name
    else:
        return random.choice(
            ["https://letsautomate.it/article/index.xml", "https://google.com", "https://github.com/swimlane/pyattck"]
        )


@pytest.mark.parametrize(
    "target_attribute",
    [
        "enterprise_attck_json",
        "pre_attck_json",
        "mobile_attck_json",
        "ics_attck_json",
        "nist_controls_json",
        "generated_nist_json",
    ],
)
def test_setting_json_locations(target_attribute):
    from pyattck import Attck

    enterprise_temp_value = get_random_file_or_url()
    pre_attck_temp_value = get_random_file_or_url()
    mobile_temp_value = get_random_file_or_url()
    ics_temp_value = get_random_file_or_url()
    nist_controls_temp_value = get_random_file_or_url()
    generated_nist_temp_value = get_random_file_or_url()

    attck = Attck(enterprise_attck_json=enterprise_temp_value)
    assert attck.config.config.enterprise_attck_json == enterprise_temp_value

    attck = Attck(pre_attck_json=pre_attck_temp_value)
    assert attck.config.config.pre_attck_json == pre_attck_temp_value

    attck = Attck(mobile_attck_json=mobile_temp_value)
    assert attck.config.config.mobile_attck_json == mobile_temp_value

    attck = Attck(ics_attck_json=ics_temp_value)
    assert attck.config.config.ics_attck_json == ics_temp_value

    attck = Attck(nist_controls_json=nist_controls_temp_value)
    assert attck.config.config.nist_controls_json == nist_controls_temp_value

    attck = Attck(generated_nist_json=generated_nist_temp_value)
    assert attck.config.config.generated_nist_json == generated_nist_temp_value


def test_passed_kwargs():
    from pyattck import Attck

    attck = Attck()
    args = {
        "verify": False,
        "proxies": {
            "http": "http://10.10.1.10:3128",
            "https": "http://10.10.1.10:1080",
        },
    }
    attck = Attck(**args)
    assert attck.config.kwargs == args
