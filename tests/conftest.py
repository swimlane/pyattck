import pytest


@pytest.fixture
def attck_fixture():
    from pyattck import Attck

    yield Attck(
        use_config=False,
        save_config=False,
        enterprise_attck_json="https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_enterprise_attck_v1.json",
        pre_attck_json="https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_pre_attck_v1.json",
        mobile_attck_json="https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_mobile_attck_v1.json",
        ics_attck_json="https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_ics_attck_v1.json",
        nist_controls_json="https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_nist_controls_v1.json",
        generated_nist_json="https://swimlane-pyattck.s3.us-west-2.amazonaws.com/attck_to_nist_controls.json",
    )


@pytest.fixture
def attck_fixture_nested_subtechniques_false():
    from pyattck import Attck

    yield Attck(nested_subtechniques=False)


@pytest.fixture
def attck_configuration():
    from pyattck.configuration import Options

    yield Options


@pytest.fixture
def attck_datasets():
    from pyattck import Attck

    yield Attck
