import os
import pytest

@pytest.fixture
def attck_fixture():
    from pyattck import Attck
    yield Attck(
        use_config=False,
        save_config=False,
        enterprise_attck_json= "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
        pre_attck_json="https://raw.githubusercontent.com/mitre/cti/master/pre-attack/pre-attack.json",
        mobile_attck_json="https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json",
        nist_controls_json="https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-control-framework-mappings/main/frameworks/attack_10_1/nist800_53_r4/stix/nist800-53-r4-controls.json",
        generated_attck_json="https://github.com/swimlane/pyattck/blob/master/generated_attck_data.json?raw=True",
        generated_nist_json="https://github.com/swimlane/pyattck/blob/master/attck_to_nist_controls.json?raw=True"
    )

@pytest.fixture
def attck_fixture_nested_subtechniques_false():
    from pyattck import Attck
    yield Attck(nested_subtechniques=False)

@pytest.fixture
def attck_configuration():
    from pyattck import Configuration
    yield Configuration

@pytest.fixture
def attck_datasets():
    from pyattck import Attck
    yield Attck