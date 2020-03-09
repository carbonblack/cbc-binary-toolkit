# -*- coding: utf-8 -*-

"""Unit tests for the ingestion actor"""

import pytest

from queue import Empty
from thespian.actors import ActorSystem, ActorExitRequest
from cbc_binary_toolkit.ingestion_actor import IngestionActor
from cbc_binary_toolkit.state import StateManager
from cbc_binary_toolkit.pubsub import PubSubManager
from cbc_binary_toolkit.config import Config
from cbapi.psc.threathunter import CbThreatHunterAPI
from tests.unit.ubs_fixtures.CBAPIMock import CBAPIMock
from tests.unit.ubs_fixtures.metadata import HASH_METADATA
from tests.unit.ubs_fixtures.filedownload import METADATA_DOWNLOAD_RESP
from tests.unit.engine_fixtures.messages import UNFINISHED_STATE, FINISHED_STATE

ENGINE_NAME = "TEST_ENGINE"


@pytest.fixture(scope="session")
def config():
    """Configuration for all the test cases in this module."""
    return Config.load(f"""
    id: cbc_binary_toolkit
    version: 0.0.1
    database:
      _provider: persistor_fixtures.mock_persistor.MockPersistorFactory
    pubsub:
      _provider: cbc_binary_toolkit.pubsub.builtin.Provider
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
def pub_sub_manager(config):
    """Creates pub_sub for IngestionActor"""
    manager = PubSubManager(config)
    manager.create_queue(ENGINE_NAME)
    return manager


@pytest.fixture(scope="function")
def actor(cb_threat_hunter, config, state_manager, pub_sub_manager):
    """Creates actor to unit test"""
    actor = ActorSystem().createActor(IngestionActor)
    ActorSystem().ask(actor, cb_threat_hunter)
    ActorSystem().ask(actor, config)
    ActorSystem().ask(actor, state_manager)
    ActorSystem().ask(actor, pub_sub_manager)
    yield actor
    ActorSystem().ask(actor, ActorExitRequest())


def mock_downloads(url, body, **kwargs):
    """Mocks the ubs _downloads route"""
    response = {
        "found": [],
        "not_found": [],
        "error": []
    }

    not_found_hashes = ["31132832bc0f3ce4a15601dc190c98b9a40a9aba1d87dae59b217610175bdfde"]

    for hash in body["sha256"]:
        if hash not in not_found_hashes:
            response["found"].append({"sha256": hash, "url": "AWS_DOWNLOAD_URL"})
    return response


@pytest.fixture(scope="function")
def cbapi_mock(monkeypatch, cb_threat_hunter):
    """Mocks CBAPI for unit tests"""
    cbapi_mock = CBAPIMock(monkeypatch, cb_threat_hunter)

    hashes = [
        "405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4",
        "0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc",
        "e02d9989cbe295518350ed3f5a04a713ece692406a9ee354785c2a4078466dcd"
    ]

    for hash in hashes:
        cbapi_mock.mock_request("GET", f"/ubs/v1/orgs/test/sha256/{hash}/metadata", HASH_METADATA[hash])

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
def test_receiveMessage_ask(actor, cbapi_mock, state_manager, pub_sub_manager, input):
    """Test receiveMessage"""
    pub_sub_queue = pub_sub_manager.get_queue(ENGINE_NAME)

    for item in input:
        completion = ActorSystem().ask(actor, item, 10)
        assert completion
        for hash in item["sha256"]:
            assert state_manager.lookup(hash, ENGINE_NAME)

    try:
        while True:
            data = pub_sub_queue._queue.get(False)
            assert data["persist_id"]
            # Remove persist_id when comparing against METADATA_DOWNLOAD_RESP
            del data["persist_id"]
            assert data == METADATA_DOWNLOAD_RESP[data["sha256"]]
    except Empty:
        pass


@pytest.mark.parametrize("input", [
    # Duplicate hashes in a single batch
    [{'sha256': ['405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4',
                 '405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4'], 'expiration_seconds': 3600}],
    # Duplicate hases in multiple batches
    [{'sha256': ['405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4'], 'expiration_seconds': 3600},
     {'sha256': ['405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4'], 'expiration_seconds': 3600}]
])
def test_duplicate_hashes(actor, cbapi_mock, state_manager, pub_sub_manager, input):
    """Test receiveMessage"""
    pub_sub_queue = pub_sub_manager.get_queue(ENGINE_NAME)

    for item in input:
        completion = ActorSystem().ask(actor, item, 10)
        assert completion
        for hash in item["sha256"]:
            assert state_manager.lookup(hash, ENGINE_NAME)

    count = 0
    try:
        while True:
            data = pub_sub_queue._queue.get(False)
            assert data["persist_id"]
            # Remove persist_id when comparing against METADATA_DOWNLOAD_RESP
            del data["persist_id"]
            assert data == METADATA_DOWNLOAD_RESP[data["sha256"]]
            count += 1
    except Empty:
        assert count == 1


@pytest.mark.parametrize("input", [
    # Hash metadata missing
    [{'sha256': ['e02d9989cbe295518350ed3f5a04a713ece692406a9ee354785c2a4078466dcd'], 'expiration_seconds': 3600}],
    # Hash not found in UBS
    [{'sha256': ['31132832bc0f3ce4a15601dc190c98b9a40a9aba1d87dae59b217610175bdfde'], 'expiration_seconds': 3600}],
    # Invalid hash
    [{'sha256': ['INVALID'], 'expiration_seconds': 3600}]
])
def test_hash_not_found(actor, cbapi_mock, state_manager, pub_sub_manager, input):
    """Test receiveMessage"""
    pub_sub_queue = pub_sub_manager.get_queue(ENGINE_NAME)

    for item in input:
        completion = ActorSystem().ask(actor, item, 10)
        assert completion
        for hash in item["sha256"]:
            assert state_manager.lookup(hash, ENGINE_NAME) is None

    assert pub_sub_queue._queue.empty()


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
def test_receiveMessage_tell(actor, cbapi_mock, state_manager, pub_sub_manager, input):
    """Test receiveMessage"""
    pub_sub_queue = pub_sub_manager.get_queue(ENGINE_NAME)

    hash_to_check = []
    for item in input:
        ActorSystem().tell(actor, item)
        hash_to_check.extend(item["sha256"])

    completion = ActorSystem().listen()
    while not completion:
        assert completion
        completion = ActorSystem().listen()

    for hash in hash_to_check:
        assert state_manager.lookup(hash, ENGINE_NAME)

    try:
        while True:
            data = pub_sub_queue._queue.get(False)
            assert data["persist_id"]
            # Remove persist_id when comparing against METADATA_DOWNLOAD_RESP
            del data["persist_id"]
            assert data == METADATA_DOWNLOAD_RESP[data["sha256"]]
    except Empty:
        pass


@pytest.mark.parametrize("input", [
    "INVALID",
    None,
    True,
    {"msg": "INVALID"},
    {"sha256": []}
])
def test_receiveMessage_invalid_messages(actor, input):
    """Test invalid messages"""
    response = ActorSystem().ask(actor, input, 1)
    assert not response


def test_restart(actor, cbapi_mock, state_manager, pub_sub_manager):
    """Test restart command"""
    UNFINISHED_STATE["engine_name"] = ENGINE_NAME
    FINISHED_STATE["engine_name"] = ENGINE_NAME
    state_manager.set_file_state("405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4", UNFINISHED_STATE)
    state_manager.set_file_state("0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc", FINISHED_STATE)

    pub_sub_queue = pub_sub_manager.get_queue(ENGINE_NAME)

    assert ActorSystem().ask(actor, ("RESTART",), 1)

    loaded = False
    processed = []
    try:
        while True:
            data = pub_sub_queue._queue.get(False)
            processed.append(data["sha256"])
            assert data["persist_id"]
            # Remove persist_id when comparing against METADATA_DOWNLOAD_RESP
            del data["persist_id"]
            assert data == METADATA_DOWNLOAD_RESP[data["sha256"]]
            loaded = True
    except Empty:
        pass
    assert loaded
    assert "0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc" not in processed
