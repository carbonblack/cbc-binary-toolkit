import pytest

from app import app as base

@pytest.fixture
def app():
    base.debug = True
    return base.test_client()


def test_analyze(app):
    body = {
        "hashes": ["1d35014d937e02ee090a0cfc903ee6e6b1b65c832694519f2b4dc4c74d3eb0fd"]
    }

    res = app.post("/analyze", json=body)
    assert res.status_code == 200
    print(res.data)
