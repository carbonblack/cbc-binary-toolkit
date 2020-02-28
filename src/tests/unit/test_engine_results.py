# -*- coding: utf-8 -*-

"""Unit tests for the engine results actor"""

import pytest
from datetime import datetime
import time
# from queue import Empty
from thespian.actors import ActorSystem, ActorExitRequest
from cbc_binary_sdk.engine_results import EngineResultsThread
from cbc_binary_sdk.ingestion_actor import IngestionActor
from cbc_binary_sdk.report_actor import ReportActor
from cbc_binary_sdk.state import StateManager
from cbc_binary_sdk.pubsub import PubSubManager
from cbc_binary_sdk.config import Config
from cbapi.psc.threathunter import CbThreatHunterAPI
from tests.unit.engine_fixtures.messages import MESSAGE_VALID
# from utils.CBAPIMock import CBAPIMock
from tests.unit.ubs_fixtures.metadata import HASH_METADATA

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
      _provider: cbc_binary_sdk.state.builtin.Persistor
      location: ":memory:"
    pubsub:
      _provider: cbc_binary_sdk.pubsub.builtin.Provider
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
    """Create result queue for engine results thread"""
    return pub_sub_manager.create_queue(ENGINE_NAME+"_results")


@pytest.fixture(scope="function")
def engine_results_thread(state_manager, pub_sub_manager, config, report_actor, result_queue, timeout=3):
    """Create engine results thread"""
    t = EngineResultsThread(kwargs={'state_manager': state_manager, 'pub_sub_manager': pub_sub_manager, 'config': config,
                                    'report_actor': report_actor, 'timeout': timeout, 'result_queue': result_queue})
    return t


# ==================================== TESTS BELOW ====================================
@pytest.mark.parametrize("engine_msg,db_init", [
    [MESSAGE_VALID, {"file_size": 1, "file_name": "testFile",
                     "os_type": "Mac", "engine_name": "TEST_ENGINE"}]
])
def test_init(state_manager, pub_sub_manager, engine_results_thread, engine_msg, db_init):
    """Test creation of engine results thread"""
    result_queue = pub_sub_manager.get_queue(ENGINE_NAME + "_results")
    hash = engine_msg.get("binary_hash", None)
    state_manager.set_file_state(hash, db_init)
    engine_results_thread.start()
    result_queue.put(engine_msg)


def test_check_timeout(engine_results_thread):
    """Test timeout check, flag not set after starting, becomes set over time"""
    engine_results_thread.start()
    assert not engine_results_thread.timeout_check.is_set()
    time.sleep(6)
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


def test_accept_report(engine_results_thread, state_manager):
    """Test adding report to item_list in state_manager"""
    # use state_manager.get_current_report_items to verify item isn't in there
    # use EngineResultsThread._accept_report to add to list
    # verify item is in list with state_manager.get_current_report_items
    pass


def test_check_completion(engine_results_thread):
    """Test completion check"""
    # need to modify EngineResultsThread._check_completion to use (currently unimplemented)
    # state_manager.get_unfinished_states. Currently EngineResultsThread._check_completion
    # only works on a clean first pass. A restart wouldn't be checked for completion correctly.

    # add a sample file to pub/sub queue with state_manager.set_file_state
    # spin up engine_results_thread
    # get the results queue with pub_sub_manager.get_queue(ENGINE_NAME + "_results"
    # put a sample engine response (MESSAGE_VALID) on results queue
    # use EngineResultsThread._update_state to signal receiving of report
    # use (modified) EngineResultsThread._check_completion to assert we've completed
