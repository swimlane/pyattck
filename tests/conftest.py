import os
import pytest

@pytest.fixture
def attck_fixture():
    from pyattck import Attck
    return Attck()

@pytest.fixture
def attck_fixture_nested_subtechniques_false():
    from pyattck import Attck
    return Attck(nested_subtechniques=False)
