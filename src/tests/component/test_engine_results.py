# -*- coding: utf-8 -*-

# *******************************************************
# Copyright (c) VMware, Inc. 2020. All Rights Reserved.
# SPDX-License-Identifier: MIT
# *******************************************************
# *
# * DISCLAIMER. THIS PROGRAM IS PROVIDED TO YOU "AS IS" WITHOUT
# * WARRANTIES OR CONDITIONS OF ANY KIND, WHETHER ORAL OR WRITTEN,
# * EXPRESS OR IMPLIED. THE AUTHOR SPECIFICALLY DISCLAIMS ANY IMPLIED
# * WARRANTIES OR CONDITIONS OF MERCHANTABILITY, SATISFACTORY QUALITY,
# * NON-INFRINGEMENT AND FITNESS FOR A PARTICULAR PURPOSE.

"""Unit tests for the engine results component."""

import pytest
import logging
import copy
from cbapi.errors import ObjectNotFoundError


from cbc_binary_toolkit.engine_results import EngineResults
from cbc_binary_toolkit.state import StateManager
from cbc_binary_toolkit.config import Config
from cbapi.psc.threathunter import CbThreatHunterAPI
from tests.component.ubs_fixtures.CBAPIMock import CBAPIMock
from tests.component.engine_fixtures.messages import (MESSAGE_VALID,
                                                      MESSAGE_VALID_1,
                                                      MESSAGE_VALID_2,
                                                      MESSAGE_INVALID,
                                                      ENGINE_FAILURE,
                                                      IOCS_1,
                                                      IOCS_2,
                                                      IOCS_3,
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
def engine_results(state_manager, cb_threat_hunter):
    """Create engine results component."""
    return EngineResults(ENGINE_NAME, state_manager, cb_threat_hunter)


# ==================================== UNIT TESTS BELOW ====================================


def test_init(state_manager, cb_threat_hunter, engine_results):
    """Test creation of engine results."""
    # engine_results_cls = engine_results(state_manager)
    assert engine_results.state_manager == state_manager
    assert engine_results.cbth == cb_threat_hunter


@pytest.mark.parametrize("engine_response", [
    copy.deepcopy(MESSAGE_VALID),
    copy.deepcopy(MESSAGE_VALID_1),
    copy.deepcopy(MESSAGE_VALID_2)
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
    """Test exception catching _update_state failure."""
    with pytest.raises(KeyError):
        assert not engine_results._update_state(engine_response["binary_hash"], engine_response["iocs"])


@pytest.mark.parametrize("engine_response", [
    {"engine_name": "Test_engine", "iocs": "string_not_list_of_iocs"},
    {"engine_name": "Test", "iocs": copy.deepcopy(IOCS_INVALID)}
])
def test_accept_report_invalid(state_manager, engine_results, engine_response):
    """Test exception catching on _accept_report failure."""
    assert not engine_results._accept_report(engine_response["engine_name"], engine_response["iocs"])


@pytest.mark.parametrize("input", [
    [{
        "id": "j39sbv7",
        "match_type": "equality",
        "values": ["127.0.0.1"],
        "severity": 1,
    }],
    [{
        "id": "j39sbv7",
        "match_type": "equality",
        "values": ["127.0.0.1"],
        "severity": 1,
    },
        {
        "id": "slkf038",
        "match_type": "equality",
        "values": ["app.exe"],
        "severity": 10,
    },
        {
        "id": "0kdl4uf9",
        "match_type": "regex",
        "values": [".*google.*"],
        "severity": 3,
    }],
])
def test_store_ioc(cbapi_mock, state_manager, engine_results, input):
    """Test _store_ioc"""
    for ioc in input:
        assert engine_results._store_ioc(ioc, ENGINE_NAME)


@pytest.mark.parametrize("input", [
    None,
    {},
    "INVALID",
    {
        "match_type": "equality",
        "values": ["127.0.0.1"],
        "severity": 1,
    },
    {
        "id": "slkf038",
        "match_type": "equality",
        "values": ["127.0.0.1"],
        "severity": 20,
    },
    {
        "id": "slkf038",
        "match_type": "equality",
        "values": ["127.0.0.1"],
        "severity": -5,
    },
    {
        "id": "slkf038",
        "match_type": "UNKNOWN",
        "values": ["127.0.0.1"],
        "severity": 10,
    },
    {
        "id": "slkf038",
        "match_type": "regex",
        "values": "127.0.0.1",
        "severity": 10,
    }
])
def test_store_ioc_invalid(cbapi_mock, state_manager, engine_results, input):
    """Test _store_ioc with invalid inputs"""
    if input:
        for ioc in input:
            assert not engine_results._store_ioc(ioc, ENGINE_NAME)
    else:
        assert not engine_results._store_ioc(input, ENGINE_NAME)


@pytest.mark.parametrize("engine_response", [
    copy.deepcopy(MESSAGE_VALID),
    copy.deepcopy(MESSAGE_VALID_1),
    copy.deepcopy(MESSAGE_VALID_2)
])
def test_validate_response(engine_results, engine_response):
    """Test EngineResponseSchema validation."""
    assert engine_results._validate_response(engine_response)


@pytest.mark.parametrize("engine_response", [
    copy.deepcopy(MESSAGE_INVALID)
])
def test_validate_response_invalid(engine_results, engine_response):
    """Test _validate_response failure."""
    assert not engine_results._validate_response(engine_response)


@pytest.mark.parametrize("engine_response", [
    copy.deepcopy(ENGINE_FAILURE)
])
def test_validate_response_invalid_1(engine_results, engine_response):
    """Test exception catching on _validate_response failure.."""
    assert not engine_results._validate_response(engine_response)


@pytest.mark.parametrize("engine_response", [
    copy.deepcopy(MESSAGE_VALID),
    copy.deepcopy(MESSAGE_VALID_1),
    copy.deepcopy(MESSAGE_VALID_2)
])
def test_execution(state_manager, engine_results, engine_response):
    """Test end to end execution of EngineResults class."""
    assert engine_results.receive_response(engine_response)


@pytest.mark.parametrize("engine_response", [
    copy.deepcopy(MESSAGE_INVALID),
    copy.deepcopy(IOCS_1),
    copy.deepcopy(IOCS_2),
    copy.deepcopy(IOCS_INVALID),
    copy.deepcopy(ENGINE_FAILURE)
])
def test_execution_fail(engine_results, engine_response):
    """Test exception catching on end to end execution failure."""
    assert not engine_results.receive_response(engine_response)


# ==================================== INTEGRATION TESTS BELOW ====================================


@pytest.mark.parametrize("engine_response", [
    copy.deepcopy(MESSAGE_VALID),
    copy.deepcopy(MESSAGE_VALID_1),
    copy.deepcopy(MESSAGE_VALID_2)
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


@pytest.mark.parametrize("input", [
    copy.deepcopy(IOCS_1),
    copy.deepcopy(IOCS_2),
    copy.deepcopy(IOCS_3)
])
def test_send_reports(cbapi_mock, state_manager, engine_results, input):
    """Test _send_reports, verifying that state_manager shows no reports after sending"""
    input_with_severity = copy.deepcopy(input)  # severity is removed when accepting report
    assert engine_results._accept_report(ENGINE_NAME, input)

    # Mock report put and send request body back
    cbapi_mock.mock_request("PUT", f"/threathunter/feedmgr/v2/orgs/test/feeds/{FEED_ID}/reports/.*", None)
    assert engine_results._send_reports(FEED_ID)
    assert ENGINE_NAME in cbapi_mock._last_request_data["title"]
    assert cbapi_mock._last_request_data["description"] == "Automated report generated by Binary Analysis SDK"

    # Check that all IOCs are attached to a report
    for ioc in input_with_severity:
        SENT = False
        log.error(f"All request data: {cbapi_mock._all_request_data}")
        for report in cbapi_mock._all_request_data:
            if ioc["severity"] == report["severity"]:
                assert len(state_manager.get_current_report_items(ioc["severity"], ENGINE_NAME)) == 0

                # Remove severity before comparison
                del ioc["severity"]
                if ioc in report["iocs_v2"]:
                    SENT = True
                break
        assert SENT


@pytest.mark.parametrize("input", [
    None,
    {},
    "INVALID",
    {
        "match_type": "equality",
        "values": ["127.0.0.1"],
        "severity": 1,
    },
    {
        "id": "slkf038",
        "match_type": "equality",
        "values": ["127.0.0.1"],
        "severity": 20,
    },
    {
        "id": "slkf038",
        "match_type": "equality",
        "values": ["127.0.0.1"],
        "severity": -5,
    },
    {
        "id": "slkf038",
        "match_type": "UNKNOWN",
        "values": ["127.0.0.1"],
        "severity": 10,
    },
    {
        "id": "slkf038",
        "match_type": "regex",
        "values": "127.0.0.1",
        "severity": 10,
    }
])
def test_send_reports_invalid(cbapi_mock, state_manager, engine_results, input):
    """Test _send_reports with invalid inputs"""
    assert not engine_results._accept_report(ENGINE_NAME, input)
    valid = engine_results._send_reports(FEED_ID)
    assert valid is False


@pytest.mark.parametrize("input", [
    copy.deepcopy(IOCS_1),
    copy.deepcopy(IOCS_2),
    copy.deepcopy(IOCS_3)
])
def test_send_reports_exception(cbapi_mock, state_manager, engine_results, input):
    """Test sending reports and an Exception being caught"""
    engine_results._accept_report(ENGINE_NAME, input)
    cbapi_mock.mock_request("PUT", f"/threathunter/feedmgr/v2/orgs/test/feeds/{'FAKE_FEED_ID'}/reports/.*", Exception)
    sent = engine_results.send_reports('FAKE_FEED_ID')
    assert not sent


@pytest.mark.parametrize("input", [
    copy.deepcopy(IOCS_1),
    copy.deepcopy(IOCS_2),
    copy.deepcopy(IOCS_3)
])
def test_send_reports_404(cbapi_mock, state_manager, engine_results, input):
    """Test receiving a 404 ObjectNotFoundError from CBAPI"""
    engine_results._accept_report(ENGINE_NAME, input)
    cbapi_mock.mock_request("PUT",
                            f"/threathunter/feedmgr/v2/orgs/test/feeds/{'FAKE_FEED_ID'}/reports/.*",
                            ObjectNotFoundError)
    sent = engine_results.send_reports('FAKE_FEED_ID')
    assert not sent


@pytest.mark.parametrize("engine_response", [
    copy.deepcopy(MESSAGE_VALID),
    copy.deepcopy(MESSAGE_VALID_1),
    copy.deepcopy(MESSAGE_VALID_2)
])
def test_reload(state_manager, engine_results, engine_response):
    """Test reloading unsent reports from state manager and sending them"""
    iocs = engine_response["iocs"]
    for ioc in iocs:
        state_manager.add_report_item(ioc["severity"], ENGINE_NAME, ioc)
    assert engine_results.reload()
    for sev in range(10):
        num_iocs_for_sev = state_manager.get_current_report_items(sev + 1, ENGINE_NAME)
        assert len(num_iocs_for_sev) == len(engine_results.iocs[sev])


def test_reload_empty(engine_results):
    """Test reloading without items in the database"""
    assert engine_results.reload()
