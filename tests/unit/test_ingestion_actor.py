# -*- coding: utf-8 -*-

"""Unit tests for the ingestion actor"""

import pytest
from thespian.actors import ActorSystem, ActorExitRequest
from cb_binary_analysis.ingestion_actor import IngestionActor
from cb_binary_analysis.state import StateManager
from cb_binary_analysis.config import Config

from cbapi.psc.threathunter import CbThreatHunterAPI
from utils.CBAPIMock import CBAPIMock


@pytest.fixture(scope="session")
def config():
    """
    Configuration for all the test cases in this module.
    """
    return Config.load("""
    id: cb-binary-analysis
    version: 0.0.1
    database:
      _provider: persistor_fixtures.persistor.MockPersistorFactory
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


@pytest.fixture(scope="function")
def cbapi_mock(monkeypatch, cb_threat_hunter):
    """Mocks CBAPI for unit tests"""
    return CBAPIMock(monkeypatch, cb_threat_hunter)


@pytest.mark.parametrize("input", [
    [],
    [{'sha256': ['405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4'], 'expiration_seconds': 3600}],
    [{'sha256': ['405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4'], 'expiration_seconds': 3600},
     {'sha256': ['6c4eb3c9e0f478b2d19a329687d113ba92c90a17d0caa6c40247a5afff31f0cd'], 'expiration_seconds': 3600}],
])
def test_receiveMessage_ask(actor, input):
    """Test receiveMessage"""
    for item in input:
        completion = ActorSystem().ask(actor, item, 10)
        assert "Completed" in completion


@pytest.mark.parametrize("input", [
    [],
    [{'sha256': ['405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4'], 'expiration_seconds': 3600}],
    [{'sha256': ['405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4'], 'expiration_seconds': 3600},
     {'sha256': ['6c4eb3c9e0f478b2d19a329687d113ba92c90a17d0caa6c40247a5afff31f0cd'], 'expiration_seconds': 3600}],
])
def test_receiveMessage_tell(actor, input):
    """Test receiveMessage"""
    for item in input:
        ActorSystem().tell(actor, item)

    completion = ActorSystem().listen()
    while completion is not None:
        assert "Completed" in completion
        completion = ActorSystem().listen()


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
