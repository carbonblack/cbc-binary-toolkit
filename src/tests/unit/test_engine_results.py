# -*- coding: utf-8 -*-

"""Unit tests for the engine results component."""

import pytest
import logging
import copy
from schema import SchemaError

from cbc_binary_toolkit.engine_results import EngineResults
from cbc_binary_toolkit.state import StateManager
from cbc_binary_toolkit.config import Config
from cbapi.psc.threathunter import CbThreatHunterAPI
from tests.unit.ubs_fixtures.CBAPIMock import CBAPIMock
from tests.unit.engine_fixtures.messages import (MESSAGE_VALID,
                                                 MESSAGE_INVALID,
                                                 ENGINE_FAILURE,
                                                 IOCS_1,
                                                 IOCS_2,
                                                 IOCS_INVALID,
                                                 UNFINISHED_STATE)

ENGINE_NAME = "TEST_ENGINE"
FEED_ID = "TEST_FEED_ID"
log = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def config():
    """Configure for all the test cases in this module."""
    return Config.load(f"""
    id: cbc_binary_toolkit
    version: 0.0.1
    database:
      _provider: cbc_binary_toolkit.state.builtin.Persistor
      location: ":memory:"
    engine:
      name: {ENGINE_NAME}
      feed_id: {FEED_ID}
      timeout: 5
    """)


@pytest.fixture(scope="session")
def cb_threat_hunter():
    """Create CbThreatHunterAPI singleton."""
    return CbThreatHunterAPI(url="https://example.com",
                             org_key="test",
                             token="abcd/1234",
                             ssl_verify=False)


@pytest.fixture(scope="function")
def cbapi_mock(monkeypatch, cb_threat_hunter):
    """Mock CBAPI for unit tests."""
    return CBAPIMock(monkeypatch, cb_threat_hunter)


@pytest.fixture(scope="function")
def state_manager(config):
    """Create state manager for ReportActor and EngineResults."""
    return StateManager(config)


@pytest.fixture(scope="function")
def engine_results(state_manager):
    """Create engine results thread."""
    return EngineResults(state_manager)


# ==================================== TESTS BELOW ====================================

def test_init(state_manager, engine_results):
    """Test creation of engine results."""
    # engine_results_cls = engine_results(state_manager)
    assert engine_results.state_manager == state_manager


@pytest.mark.parametrize("engine_response", [
    copy.deepcopy(MESSAGE_VALID)
])
def test_update_state(state_manager, engine_results, engine_response):
    """Test setting the checkpoint for valid response."""
    assert engine_results._validate_response(engine_response)
    assert engine_results._update_state(engine_response["binary_hash"], engine_response["engine_name"])


@pytest.mark.parametrize("engine_response", [
    copy.deepcopy(MESSAGE_INVALID),
    copy.deepcopy(UNFINISHED_STATE)
])
def test_update_state_invalid(state_manager, engine_results, engine_response):
    """Test raising exception on _update_state failure."""
    with pytest.raises(Exception):
        assert not engine_results._update_state(engine_response["binary_hash"], engine_response["iocs"])


@pytest.mark.parametrize("engine_response", [
    copy.deepcopy(MESSAGE_VALID)
])
def test_accept_report(state_manager, engine_results, engine_response):
    """Test accepting a report/adding it to the state_manager's list."""
    engine_name = engine_response["engine_name"]
    assert engine_results._accept_report(engine_name, engine_response["iocs"])
    current_report_items = []
    for severity in range(1, 11):
        current_report_items.extend(state_manager.get_current_report_items(severity, engine_name))
    assert len(current_report_items) == len(engine_response["iocs"])
    for report in current_report_items:
        assert report in engine_response["iocs"]


@pytest.mark.parametrize("engine_response", [
    {"engine_name": "Test_engine", "iocs": "string_not_list_of_iocs"},
    {"engine_name": "Test", "iocs": copy.deepcopy(IOCS_INVALID)}
])
def test_accept_report_invalid(state_manager, engine_results, engine_response):
    """Test raising exception on _accept_report failure."""
    with pytest.raises(SchemaError):
        assert not engine_results._accept_report(engine_response["engine_name"], engine_response["iocs"])


@pytest.mark.parametrize("engine_response", [
    copy.deepcopy(MESSAGE_VALID)
])
def test_validate_response(engine_results, engine_response):
    """Test EngineResponseSchema validation."""
    assert engine_results._validate_response(engine_response)


@pytest.mark.parametrize("engine_response", [
    copy.deepcopy(MESSAGE_INVALID)
])
def test_validate_response_invalid(engine_results, engine_response):
    """Test raising exception on _validate_response failure."""
    with pytest.raises(KeyError):
        assert not engine_results._validate_response(engine_response)


@pytest.mark.parametrize("engine_response", [
    copy.deepcopy(ENGINE_FAILURE)
])
def test_validate_response_invalid_1(engine_results, engine_response):
    """Test raising exception on _validate_response failure.."""
    assert not engine_results._validate_response(engine_response)


@pytest.mark.parametrize("engine_response", [
    copy.deepcopy(MESSAGE_VALID)
])
def test_execution(state_manager, engine_results, engine_response):
    """Test end to end execution of EngineResults class."""
    assert engine_results.receive_response(engine_response)


@pytest.mark.parametrize("engine_response", [
    copy.deepcopy(MESSAGE_INVALID)
])
def test_execution_fail_key_error(engine_results, engine_response):
    """Test rasing exception on end to end execution failure."""
    with pytest.raises(KeyError):
        assert not engine_results.receive_response(engine_response)


@pytest.mark.parametrize("engine_response", [
    copy.deepcopy(IOCS_1),
    copy.deepcopy(IOCS_2),
    copy.deepcopy(IOCS_INVALID)
])
def test_execution_fail_type_error(engine_results, engine_response):
    """Test rasing exception on end to end execution failure."""
    with pytest.raises(TypeError):
        assert not engine_results.receive_response(engine_response)


@pytest.mark.parametrize("engine_response", [
    copy.deepcopy(ENGINE_FAILURE)
])
def test_execution_engine_failure(engine_results, engine_response):
    """Test end to end failure when engine_response['success'] == false."""
    assert not engine_results.receive_response(engine_response)
