import os
import pytest

@pytest.fixture
def attck_fixture():
    from pyattck import Attck
    return Attck()