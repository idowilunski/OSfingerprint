# test_your_module.py
import pytest

@pytest.fixture
def setup_data():
    data = {'key': 'value'}
    return data

def test_something_with_fixture(setup_data):
    assert setup_data['key'] == 'value'
