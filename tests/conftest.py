import os
import pytest

@pytest.fixture
def attck_fixture():
    from pyattck import Attck
    return Attck()

@pytest.fixture
def attck_fixture_subtechniques():
    from pyattck import Attck
    return Attck(subtechniques=True)