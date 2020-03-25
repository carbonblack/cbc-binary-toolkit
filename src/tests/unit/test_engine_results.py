# -*- coding: utf-8 -*-

"""Unit tests for the engine results actor"""

import pytest
import time
import logging
import copy

# from queue import Empty
from thespian.actors import ActorSystem, ActorExitRequest

from cbc_binary_toolkit import InitializationError
from cbc_binary_toolkit.engine_results import EngineResultsThread
from cbc_binary_toolkit.report_actor import ReportActor
from cbc_binary_toolkit.state import StateManager
from cbc_binary_toolkit.pubsub import PubSubManager
from cbc_binary_toolkit.config import Config
from cbapi.psc.threathunter import CbThreatHunterAPI
from tests.unit.ubs_fixtures.CBAPIMock import CBAPIMock
from tests.unit.engine_fixtures.messages import (MESSAGE_VALID,
                                                 MESSAGE_INVALID,
                                                 ENGINE_FAILURE,
                                                 IOCS_1,
                                                 IOCS_2,
                                                 UNFINISHED_STATE,
                                                 FINISHED_STATE)

ENGINE_NAME = "TEST_ENGINE"
FEED_ID = "TEST_FEED_ID"
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
      feed_id: {FEED_ID}
      timeout: 5
    """)


@pytest.fixture(scope="session")
def cb_threat_hunter():
    """Create CbThreatHunterAPI singleton"""
    return CbThreatHunterAPI(url="https://example.com",
                             org_key="test",
                             token="abcd/1234",
                             ssl_verify=False)


@pytest.fixture(scope="function")
def cbapi_mock(monkeypatch, cb_threat_hunter):
    """Mocks CBAPI for unit tests"""
    return CBAPIMock(monkeypatch, cb_threat_hunter)


@pytest.fixture(scope="function")
def state_manager(config):
    """Creates state manager for ReportActor and EngineResultsThread"""
    return StateManager(config)


@pytest.fixture(scope="function")
def pub_sub_manager(config):
    """Creates pub_sub for EngineResultsThread"""
    manager = PubSubManager(config)
    manager.create_queue(ENGINE_NAME)
    manager.create_queue(config.string("pubsub.result_queue_name"))
    return manager


@pytest.fixture(scope="function")
def report_actor(cb_threat_hunter, state_manager):
    """Creates report actor to unit test"""
    log.debug("Init report_actor in pytest")
    actor = ActorSystem().createActor(ReportActor)
    ActorSystem().ask(actor, cb_threat_hunter)
    ActorSystem().ask(actor, state_manager)
    ActorSystem().ask(actor, ENGINE_NAME)
    yield actor
    ActorSystem().ask(actor, ActorExitRequest())


@pytest.fixture(scope="function")
def engine_results_thread(state_manager, pub_sub_manager, config, report_actor):
    """Create engine results thread"""
    return EngineResultsThread(kwargs={'state_manager': state_manager,
                                       'pub_sub_manager': pub_sub_manager,
                                       'config': config,
                                       'report_actor': report_actor})


# ==================================== TESTS BELOW ====================================

@pytest.mark.xfail()
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


@pytest.mark.parametrize("db_init", [
    copy.deepcopy(IOCS_1)
])
def test_restart(config, cbapi_mock, pub_sub_manager, report_actor, state_manager, db_init):
    """Test restart of engine results thread"""
    cbapi_mock.mock_request("PUT", f"/threathunter/feedmgr/v2/orgs/test/feeds/{FEED_ID}/reports/.*", None)

    for ioc in db_init:
        state_manager.add_report_item(ioc["severity"], config.get("engine.name"), ioc)

    EngineResultsThread(kwargs={'state_manager': state_manager,
                                'pub_sub_manager': pub_sub_manager,
                                'config': config,
                                'report_actor': report_actor})

    # Verify that EngineResultsThread loaded reports and sent them to the report actor
    assert ActorSystem().ask(report_actor, ("SEND_REPORTS", FEED_ID), 1) is True

    for ioc in db_init:
        SENT = False
        for report in cbapi_mock._all_request_data:
            if ioc["severity"] == report["severity"]:
                assert len(state_manager.get_current_report_items(ioc["severity"], ENGINE_NAME)) == 0

                # Remove severity before comparison
                del ioc["severity"]
                if ioc in report["iocs_v2"]:
                    SENT = True
                break
        assert SENT


@pytest.mark.parametrize("kwargs", [
    None,
    {"invalid": "invalid"}
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


@pytest.mark.xfail()
@pytest.mark.parametrize("message,db_init", [
    [MESSAGE_VALID, {"file_size": 50, "file_name": "testFile",
                     "os_type": "Mac", "engine_name": "TEST_ENGINE"}],
    [ENGINE_FAILURE, {"file_size": 50, "file_name": "testFile",
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
    [copy.deepcopy(IOCS_1)],
    [copy.deepcopy(IOCS_1), copy.deepcopy(IOCS_2)]
])
def test_accept_report(engine_results_thread, state_manager, iocs):
    """Test adding report to item_list in state_manager"""
    for ioc_group in iocs:
        engine_results_thread._accept_report(ENGINE_NAME, ioc_group)
        for ioc in ioc_group:
            assert ioc in state_manager.get_current_report_items(ioc["severity"], ENGINE_NAME)


@pytest.mark.xfail()
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


@pytest.mark.xfail()
@pytest.mark.parametrize("analysis,state", [
    (MESSAGE_VALID, UNFINISHED_STATE),
])
def test_execution(engine_results_thread, cbapi_mock, config, state_manager, pub_sub_manager, analysis, state):
    """Test end to end of EngineResultsThread"""
    analysis["engine_name"] = ENGINE_NAME
    state["engine_name"] = ENGINE_NAME

    cbapi_mock.mock_request("PUT", f"/threathunter/feedmgr/v2/orgs/test/feeds/{FEED_ID}/reports/.*", None)

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


@pytest.mark.xfail()
@pytest.mark.parametrize("analysis,state", [
    (MESSAGE_INVALID, UNFINISHED_STATE),
])
def test_failed_execution(engine_results_thread, cbapi_mock, config, state_manager, pub_sub_manager, analysis, state):
    """Test end to end of EngineResultsThread"""
    analysis["engine_name"] = ENGINE_NAME
    state["engine_name"] = ENGINE_NAME

    cbapi_mock.mock_request("PUT", f"/threathunter/feedmgr/v2/orgs/test/feeds/{FEED_ID}/reports/.*", None)

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
    assert "time_returned" not in hash_state
