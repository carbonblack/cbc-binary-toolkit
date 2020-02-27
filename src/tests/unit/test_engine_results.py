# -*- coding: utf-8 -*-

"""Unit tests for the engine results actor"""

import pytest
from datetime import datetime
# from queue import Empty
from thespian.actors import ActorSystem, ActorExitRequest
from cb_binary_analysis.engine_results import EngineResultsThread
from cb_binary_analysis.ingestion_actor import IngestionActor
from cb_binary_analysis.report_actor import ReportActor
from cb_binary_analysis.state import StateManager
from cb_binary_analysis.pubsub import PubSubManager
from cb_binary_analysis.config import Config
from cbapi.psc.threathunter import CbThreatHunterAPI
from tests.unit.engine_fixtures.messages import MESSAGE_VALID
from utils.CBAPIMock import CBAPIMock
from tests.unit.ubs_fixtures.metadata import HASH_METADATA
from tests.unit.ubs_fixtures.filedownload import METADATA_DOWNLOAD_RESP

import logging
ENGINE_NAME = "TEST_ENGINE"
log = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def config():
    """Configuration for all the test cases in this module."""
    return Config.load(f"""
    id: cb-binary-analysis
    version: 0.0.1
    database:
      _provider: cb_binary_analysis.state.builtin.Persistor
      location: ":memory:"
    pubsub:
      _provider: cb_binary_analysis.pubsub.builtin.Provider
    engine:
      name: {ENGINE_NAME}
    """)


@pytest.fixture(scope="session")
def cb_threat_hunter():
    """Create CbThreatHunterAPI singleton"""
    return CbThreatHunterAPI(url="https://example.com",
                             org_key="test",
                             token="abcd/1234",
                             ssl_verify=False)


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


@pytest.fixture(scope="function")
def state_manager(config):
    """Creates state manager for IngestionActor"""
    return StateManager(config)


@pytest.fixture(scope="function")
def pub_sub_manager(config):
    """Creates pub_sub for IngestionActor"""
    manager = PubSubManager(config)
    manager.create_queue(ENGINE_NAME)
    return manager

#
# @pytest.fixture(scope="function")
# def sent_reports(state_manager):
#     """Creates dict of sent reports for engine actor"""
#     return state_manager.get_hashes_by_engine()


@pytest.fixture(scope="function")
def ingestion_actor(cb_threat_hunter, config, state_manager, pub_sub_manager):
    """Creates ingestion actor to unit test"""
    actor = ActorSystem().createActor(IngestionActor)
    ActorSystem().ask(actor, cb_threat_hunter)
    ActorSystem().ask(actor, config)
    ActorSystem().ask(actor, state_manager)
    ActorSystem().ask(actor, pub_sub_manager)
    yield actor
    ActorSystem().ask(actor, ActorExitRequest())


@pytest.fixture(scope="function")
def report_actor(cb_threat_hunter):
    """Creates report actor to unit test"""
    log.debug("Init report_actor in pytest")
    actor = ActorSystem().createActor(ReportActor)
    ActorSystem().ask(actor, cb_threat_hunter)
    ActorSystem().ask(actor, ENGINE_NAME)
    yield actor
    ActorSystem().ask(actor, ActorExitRequest())

@pytest.fixture(scope="function")
def result_queue(pub_sub_manager):
    return pub_sub_manager.create_queue(ENGINE_NAME+"_results")

@pytest.fixture(scope="function")
def engine_results_thread(state_manager, pub_sub_manager, config, report_actor, result_queue, timeout=3):
    t = EngineResultsThread(kwargs={'state_manager': state_manager, 'pub_sub_manager': pub_sub_manager, 'config': config,
                                    'report_actor': report_actor, 'timeout': timeout, 'result_queue': result_queue})
    return t
# # @pytest.fixture(scope="function")
# def engine_actor(state_manager, pub_sub_manager, config, report_actor, timeout):
#     """Creates engine_results actor to unit test"""
#     actor = ActorSystem().createActor(EngineResultsActor)
#     ActorSystem().ask(actor, state_manager)
#     ActorSystem().ask(actor, pub_sub_manager)
#     ActorSystem().ask(actor, config)
#     # ActorSystem().ask(actor, (ingestion_actor, report_actor))
#     ActorSystem().ask(actor, report_actor)
#     ActorSystem().ask(actor, state_manager.get_hashes_by_engine())
#     ActorSystem().ask(actor, timeout)
#     return actor
#     # ActorSystem().ask(actor, ActorExitRequest())


# ==================================== TESTS BELOW ====================================
@pytest.mark.parametrize("engine_msg,db_init", [
    [MESSAGE_VALID, {"file_size": 1, "file_name": "testFile",
                     "os_type": "Mac", "engine_name": "TEST_ENGINE"}]
])
def test_init(state_manager, pub_sub_manager, engine_results_thread, engine_msg, db_init):

    result_queue = pub_sub_manager.get_queue(ENGINE_NAME+"_results")
    hash = engine_msg.get("binary_hash", None)
    state_manager.set_file_state(hash, db_init)
    engine_results_thread.start()

    result_queue.put(engine_msg)
    # engine_results_thread.join()
    assert True
# @pytest.mark.parametrize("message", [
#     ActorExitRequest()
# ])
# def test_receiveMessage_ExitRequest(state_manager, pub_sub_manager, config, report_actor, message):
#     """Test receiveMsg_ActorExitRequest"""
#     engine = engine_actor(state_manager, pub_sub_manager, config, report_actor, 1)
#     eng = next(engine)
#     assert ActorSystem().ask(eng, message, 10) is None
#     # ActorSystem().ask(eng, ActorExitRequest())
#
#
# @pytest.mark.parametrize("message,db_init", [
#     [MESSAGE_VALID, {"file_size": 50, "file_name": "testFile",
#                      "os_type": "Mac", "engine_name": "TEST_ENGINE"}]
# ])
# def test_receiveMessage_ask(state_manager, pub_sub_manager, config, report_actor, message, db_init):
#     """Test receiveMessage"""
#     hash = message.get("binary_hash", None)
#     state_manager.set_file_state(hash, db_init)
#     engine = engine_actor(state_manager, pub_sub_manager, config, report_actor, 1)
#     eng = next(engine)
#     assert ActorSystem().ask(eng, message, 10)
#     assert state_manager.lookup(hash, ENGINE_NAME)
#     # ActorSystem().ask(eng, ActorExitRequest())
#
#
# @pytest.mark.parametrize("message,db_init", [
#     [MESSAGE_VALID, {"file_size": 1, "file_name": "testFile",
#                      "os_type": "Mac", "engine_name": "TEST_ENGINE"}]
# ])
# def test_receiveMessage_tell(state_manager, pub_sub_manager, config, report_actor, message, db_init):
#     """Test receiveMessage"""
#     hash = message.get("binary_hash", None)
#     state_manager.set_file_state(hash, db_init)
#     engine = engine_actor(state_manager, pub_sub_manager, config, report_actor, 1)
#     eng = next(engine)
#     ActorSystem().tell(eng, message)
#     valid = ActorSystem().listen()
#     assert valid
#     assert state_manager.lookup(hash, ENGINE_NAME)
#     # ActorSystem().ask(eng, ActorExitRequest())
#
#
# @pytest.mark.parametrize("message", [
#     "This_isn't_a_valid_message",
#     None,
#     0,
#     [],
#     False
# ])
# def test_receiveMessage_invalid(state_manager, pub_sub_manager, config, report_actor, message):
#     """Test receiveMessage with invalid msgs"""
#     engine = engine_actor(state_manager, pub_sub_manager, config, report_actor, 1)
#     eng = next(engine)
#     assert not ActorSystem().ask(eng, message)
#     # ActorSystem().ask(eng, ActorExitRequest())

# adjust for cbapi_mock
# @pytest.mark.parametrize("engine_msg,db_init", [
#     [MESSAGE_VALID, {"file_size": 1, "file_name": "testFile",
#                      "os_type": "Mac", "engine_name": "TEST_ENGINE"}]
# ])
# def test_receiveMessage_completion(state_manager, pub_sub_manager, config, report_actor, engine_msg, db_init):
#     """Test receiveMessage"""
#     # ingest = ActorSystem().ask(ingestion_actor, ingest_input, 10)
#     # assert "Completed" in ingest
#     hash = engine_msg.get("binary_hash", None)
#     state_manager.set_file_state(hash, db_init)
#     # sent_reports = state_manager.get_hashes_by_engine()
#     # log.debug(f"Sent_reports in test function, being passed to engine actor: {sent_reports}")
#     engine = engine_actor(state_manager, pub_sub_manager, config, report_actor, 5)
#     eng = engine
#     result_queue = pub_sub_manager.get_queue("Results")
#     # breakpoint()
#     result_queue.put(engine_msg)
#     # result_queue.put(engine_msg)
#
#
#     ActorSystem().ask(eng, ActorExitRequest())
    # x = ActorSystem().ask(next(engine), engine_msg, 10)
    # assert x
    # assert False
