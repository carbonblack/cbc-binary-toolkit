# -*- coding: utf-8 -*-

"""Unit tests for the ingestion actor"""

import pytest
from thespian.actors import ActorSystem, ActorExitRequest
from cb_binary_analysis.ingestion_actor import IngestionActor
from cb_binary_analysis.state import StateManager
from cb_binary_analysis.config import Config

from cbapi.psc.threathunter import CbThreatHunterAPI
from utils.CBAPIMock import CBAPIMock
from tests.unit.ubs_fixtures.metadata import hash_metadata

ENGINE_NAME = "TEST_ENGINE"


@pytest.fixture(scope="session")
def config():
    """Configuration for all the test cases in this module."""
    return Config.load(f"""
    id: cb-binary-analysis
    version: 0.0.1
    database:
      _provider: persistor_fixtures.mock_persistor.MockPersistorFactory
    engine:
      name: {ENGINE_NAME}
    """)


@pytest.fixture(scope="function")
def state_manager(config):
    """Creates state manager for IngestionActor"""
    return StateManager(config)


@pytest.fixture(scope="session")
def cb_threat_hunter():
    """Create CbThreatHunterAPI singleton"""
    return CbThreatHunterAPI(url="https://example.com",
                             org_key="test",
                             token="abcd/1234",
                             ssl_verify=False)


@pytest.fixture(scope="function")
def actor(cb_threat_hunter, config, state_manager):
    """Creates actor to unit test"""
    actor = ActorSystem().createActor(IngestionActor)
    ActorSystem().ask(actor, cb_threat_hunter)
    ActorSystem().ask(actor, config)
    ActorSystem().ask(actor, state_manager)
    yield actor
    ActorSystem().ask(actor, ActorExitRequest())


def mock_downloads(url, body, **kwargs):
    """Mocks the ubs _downloads route"""
    response = {
        "found": [],
        "not_found": [],
        "error": []
    }

    for hash in body["sha256"]:
        response["found"].append({"sha256": hash, "url": "AWS_FAKE_URL"})
    return response


@pytest.fixture(scope="function")
def cbapi_mock(monkeypatch, cb_threat_hunter):
    """Mocks CBAPI for unit tests"""
    cbapi_mock = CBAPIMock(monkeypatch, cb_threat_hunter)

    hashes = [
        "405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4",
        "0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc"
    ]

    for hash in hashes:
        cbapi_mock.mock_request("GET", f"/ubs/v1/orgs/test/sha256/{hash}/metadata", hash_metadata[hash])

    cbapi_mock.mock_request("POST", f"/ubs/v1/orgs/test/file/_download", mock_downloads)
    return cbapi_mock


# ==================================== TESTS BELOW ====================================


@pytest.mark.parametrize("input", [
    # Single hash in a single batch
    [{'sha256': ['405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4'], 'expiration_seconds': 3600}],
    # Multiple hashes in a single batch
    [{'sha256': ['405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4',
                 '0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc'], 'expiration_seconds': 3600}],
    # Multiple batches
    [{'sha256': ['405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4'], 'expiration_seconds': 3600},
     {'sha256': ['0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc'], 'expiration_seconds': 3600}]
])
def test_receiveMessage_ask(actor, cbapi_mock, state_manager, input):
    """Test receiveMessage"""
    for item in input:
        completion = ActorSystem().ask(actor, item, 10)
        assert "Completed" in completion
        for hash in item["sha256"]:
            assert state_manager.lookup(hash, ENGINE_NAME)


@pytest.mark.parametrize("input", [
    # Single hash in a single batch
    [{'sha256': ['e02d9989cbe295518350ed3f5a04a713ece692406a9ee354785c2a4078466dcd'], 'expiration_seconds': 3600}],
])
def test_hash_not_found(actor, cbapi_mock, state_manager, input):
    """Test receiveMessage"""
    for item in input:
        completion = ActorSystem().ask(actor, item, 10)
        assert "Completed" in completion
        for hash in item["sha256"]:
            assert state_manager.lookup(hash, ENGINE_NAME)


@pytest.mark.parametrize("input", [
    # Single hash in a single batch
    [{'sha256': ['405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4'], 'expiration_seconds': 3600}],
    # Multiple hashes in a single batch
    [{'sha256': ['405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4',
                 '0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc'], 'expiration_seconds': 3600}],
    # Multiple batches
    [{'sha256': ['405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4'], 'expiration_seconds': 3600},
     {'sha256': ['0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc'], 'expiration_seconds': 3600}]
])
def test_receiveMessage_tell(actor, cbapi_mock, state_manager, input):
    """Test receiveMessage"""
    hash_to_check = []
    for item in input:
        ActorSystem().tell(actor, item)
        hash_to_check.extend(item["sha256"])

    completion = ActorSystem().listen()
    while completion is not None:
        assert "Completed" in completion
        completion = ActorSystem().listen()

    for hash in hash_to_check:
        assert state_manager.lookup(hash, ENGINE_NAME)


@pytest.mark.parametrize("input", [
    "INVALID",
    None,
    True,
    {"msg": "INVALID"},
])
def test_receiveMessage_invalid_messages(actor, input):
    """Test invalid messages"""
    response = ActorSystem().ask(actor, input, 1)
    assert "Invalid message format expected" in response
