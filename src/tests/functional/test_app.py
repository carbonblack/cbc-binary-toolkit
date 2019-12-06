import pytest
import json

from app import app as base

@pytest.fixture
def app():
    base.debug = True
    return base.test_client()

def test_analyze_no_queues(app):
    body = {
        "hashes": ["1d35014d937e02ee090a0cfc903ee6e6b1b65c832694519f2b4dc4c74d3eb0fd"]
    }

    res = app.post("/analyze", json=body)
    assert res.status_code == 424
    assert json.loads(res.data)["success"] is False

def test_queue_post(app):
    body = {
        "key": "test"
    }

    res = app.post("/queues", json=body)
    assert res.status_code == 200
    assert json.loads(res.data)["success"] is True

def test_analyze_success(app):
    body = {
        "hashes": ["1d35014d937e02ee090a0cfc903ee6e6b1b65c832694519f2b4dc4c74d3eb0fd"]
    }

    res = app.post("/analyze", json=body)
    assert res.status_code == 200
    assert json.loads(res.data)["success"] is True

def test_queue_delete(app):
    body = {
        "key": "test"
    }

    res = app.delete("/queues", json=body)
    assert res.status_code == 204
    assert res.data is b''

def test_queue_delete_missing(app):
    body = {
        "key": "test"
    }

    res = app.delete("/queues", json=body)
    assert res.status_code == 404
    assert json.loads(res.data)["success"] is False
