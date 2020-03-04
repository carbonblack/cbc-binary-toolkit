# -*- coding: utf-8 -*-

"""Unit tests for the engine results actor"""

import pytest
import time
# from queue import Empty
from thespian.actors import ActorSystem, ActorExitRequest

from cbc_binary_toolkit import InitializationError
from cbc_binary_toolkit.engine_results import EngineResultsThread
from cbc_binary_toolkit.ingestion_actor import IngestionActor
from cbc_binary_toolkit.report_actor import ReportActor
from cbc_binary_toolkit.state import StateManager
from cbc_binary_toolkit.pubsub import PubSubManager
from cbc_binary_toolkit.config import Config
from cbapi.psc.threathunter import CbThreatHunterAPI
from tests.unit.engine_fixtures.messages import MESSAGE_VALID, IOCS_1, IOCS_2, UNFINISHED_STATE, FINISHED_STATE

import logging
ENGINE_NAME = "TEST_ENGINE"
log = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def config():
    """Configuration for all the test cases in this module."""
    return Config.load(f"""
    id: cbc_binary_toolkit
    version: 0.0.1
    database:
      _provider: cbc_binary_toolkit.state.builtin.Persistor
      location: ":memory:"
    pubsub:
      _provider: cbc_binary_toolkit.pubsub.builtin.Provider
      result_queue_name: results
    engine:
      name: {ENGINE_NAME}
      feed_id: TEST_FEED_ID
    """)


@pytest.fixture(scope="session")
def cb_threat_hunter():
    """Create CbThreatHunterAPI singleton"""
    return CbThreatHunterAPI(url="https://example.com",
                             org_key="test",
                             token="abcd/1234",
                             ssl_verify=False)


@pytest.fixture(scope="function")
def state_manager(config):
    """Creates state manager for IngestionActor"""
    return StateManager(config)


@pytest.fixture(scope="function")
def pub_sub_manager(config):
    """Creates pub_sub for IngestionActor"""
    manager = PubSubManager(config)
    manager.create_queue(ENGINE_NAME)
    manager.create_queue(config.string("pubsub.result_queue_name"))
    return manager


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
def engine_results_thread(state_manager, pub_sub_manager, config, report_actor, timeout=5):
    """Create engine results thread"""
    return EngineResultsThread(kwargs={'state_manager': state_manager,
                                       'pub_sub_manager': pub_sub_manager,
                                       'config': config,
                                       'report_actor': report_actor,
                                       'timeout': timeout})


# ==================================== TESTS BELOW ====================================
@pytest.mark.parametrize("engine_msg,db_init", [
    [MESSAGE_VALID, {"file_size": 1, "file_name": "testFile",
                     "os_type": "Mac", "engine_name": "TEST_ENGINE"}]
])
def test_init(config, state_manager, pub_sub_manager, engine_results_thread, engine_msg, db_init):
    """Test creation of engine results thread"""
    hash = engine_msg.get("binary_hash", None)
    state_manager.set_file_state(hash, db_init)
    engine_results_thread.start()
    pub_sub_manager.put(config.string("pubsub.result_queue_name"), engine_msg)


@pytest.mark.parametrize("kwargs", [
    None,
    {"timeout": 5}
])
def test_init_exception(kwargs):
    """Test invalid init"""
    with pytest.raises(InitializationError):
        EngineResultsThread(kwargs=kwargs)


def test_check_timeout(engine_results_thread):
    """Test timeout check, flag not set after starting, becomes set over time"""
    engine_results_thread.start()
    assert not engine_results_thread.timeout_check.is_set()
    time.sleep(7)
    assert engine_results_thread.timeout_check.is_set()


@pytest.mark.parametrize("message,db_init", [
    [MESSAGE_VALID, {"file_size": 50, "file_name": "testFile",
                     "os_type": "Mac", "engine_name": "TEST_ENGINE"}]
])
def test_update_state(engine_results_thread, state_manager, message, db_init):
    """Test updating hash state in state manager"""
    hash = message.get("binary_hash", None)
    state_manager.set_file_state(hash, db_init)
    info_before_update = state_manager.lookup(hash, ENGINE_NAME)
    engine_results_thread._update_state(hash, ENGINE_NAME)
    info_after_update = state_manager.lookup(hash, ENGINE_NAME)
    assert "time_returned" not in info_before_update
    assert "time_returned" in info_after_update


@pytest.mark.parametrize("iocs", [
    [IOCS_1],
    [IOCS_1, IOCS_2]
])
def test_accept_report(engine_results_thread, state_manager, iocs):
    """Test adding report to item_list in state_manager"""
    for ioc_group in iocs:
        engine_results_thread._accept_report(ENGINE_NAME, ioc_group)
        for ioc in ioc_group:
            assert ioc in state_manager.get_current_report_items(ioc["severity"], ENGINE_NAME)


@pytest.mark.parametrize("state,expected", [
    [None, False],
    [UNFINISHED_STATE, False],
    [FINISHED_STATE, True]
])
def test_check_completion(engine_results_thread, state_manager, state, expected):
    """Test completion check"""
    if state:
        state["engine_name"] = ENGINE_NAME
        state_manager.set_file_state("HASH", state)
    assert engine_results_thread._check_completion(ENGINE_NAME) == expected


@pytest.mark.parametrize("analysis,state", [
    (MESSAGE_VALID, UNFINISHED_STATE),
])
def test_execution(engine_results_thread, config, state_manager, pub_sub_manager, analysis, state):
    """Test end to end of EngineResultsThread"""
    analysis["engine_name"] = ENGINE_NAME
    state["engine_name"] = ENGINE_NAME

    # Set processed state
    state_manager.set_file_state(analysis["binary_hash"], state)

    # Add analysis to pubsub
    pub_sub_manager.put(config.string("pubsub.result_queue_name"), analysis)

    # Start analysis processing thread
    engine_results_thread.start()

    # Wait for thread to exit
    engine_results_thread.join()

    # Check hash has returned timestamp
    hash_state = state_manager.lookup(analysis["binary_hash"], ENGINE_NAME)
    assert hash_state["time_returned"]
