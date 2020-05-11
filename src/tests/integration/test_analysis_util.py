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

"""Tests for the AnalysisUtility 'top-level' object"""

import pytest
import logging
import copy
import json
from argparse import Namespace
from datetime import datetime, timedelta

from cbapi.psc.threathunter import CbThreatHunterAPI
from cbc_binary_toolkit.config import Config
from cbc_binary_toolkit.state.manager import StateManager
from cbc_binary_toolkit_examples.tools.analysis_util import AnalysisUtility
from tests.component.engine_fixtures.messages import IOCS_2
from tests.component.ubs_fixtures.CBAPIMock import CBAPIMock
from tests.component.ubs_fixtures.metadata import METADATA_VALID

logging.basicConfig(level=logging.DEBUG)


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


ENGINE_NAME = "MockEngine"
FEED_ID = "TEST_FEED_ID"


@pytest.fixture(scope="session")
def config():
    """Configure for most of the test cases in this module."""
    return Config.load(f"""
    id: cbc_binary_toolkit
    version: 0.0.1
    database:
      _provider: cbc_binary_toolkit.state.builtin.Persistor
      location: ":memory:"
    engine:
      _provider: tests.component.engine_fixtures.mock_engine.MockLocalEngineFactory
      name: {ENGINE_NAME}
      feed_id: {FEED_ID}
      type: local
      Test: TestPassed
    """)


@pytest.fixture(scope="session")
def config2():
    """Configure for one of the restart tests."""
    return Config.load(f"""
    id: cbc_binary_toolkit
    version: 0.0.1
    database:
      _provider: tests.component.persistor_fixtures.mock_persistor.MockPersistorFactory
    engine:
      _provider: tests.component.engine_fixtures.mock_engine.MockLocalEngineFactory
      name: {ENGINE_NAME}
      feed_id: {FEED_ID}
      type: local
      Test: TestPassed
    """)


@pytest.fixture(scope="session")
def config3():
    """Configure for one of the restart tests."""
    return Config.load(f"""
    id: cbc_binary_toolkit
    version: 0.0.1
    database:
      _provider: tests.component.persistor_fixtures.mock_persistor.MockPersistorFactory
    engine:
      _provider: tests.component.engine_fixtures.mock_engine.MockLocalEngineFactory
      name: {ENGINE_NAME}
      type: local
      Test: TestPassed
    """)


def minus_severity(iocs):
    """Removes "severity" from all the IOC structures, for comparison purposes"""
    tmp = copy.deepcopy(iocs)
    return_value = []
    for ioc in tmp:
        del ioc["severity"]
        return_value.append(ioc)
    return return_value


def ensure_not_report(request_data):
    """Validates that the request data is not for a report"""
    assert "title" not in request_data
    assert "description" not in request_data
    assert "severity" not in request_data
    assert "iocs_v2" not in request_data

# These are INTEGRATION TESTS that test that data is flowing correctly through all components


def test_any_reports_present_yes(config):
    """Does _any_reports_present return True correctly?"""
    state_manager = StateManager(config)
    state_manager.add_report_item(6, ENGINE_NAME, {'keyval': 1})
    sut = AnalysisUtility(None)
    sut.config = config
    assert sut._any_reports_present(state_manager)


def test_any_reports_present_no(config):
    """Does _any_reports_present return False correctly?"""
    state_manager = StateManager(config)
    sut = AnalysisUtility(None)
    sut.config = config
    assert not sut._any_reports_present(state_manager)


def test_process_metadata(cbapi_mock, config):
    """Test data flow through the components in the _process_metadata method"""
    sut = AnalysisUtility(None)
    sut.config = config
    sut.cbapi = cbapi_mock.api
    cbapi_mock.mock_request("PUT", f"/threathunter/feedmgr/v2/orgs/test/feeds/{FEED_ID}/reports/.*", None)

    components = sut._init_components()
    components["engine_manager"].engine.mock_engine_output(METADATA_VALID["sha256"], IOCS_2)

    sut._process_metadata(components, [METADATA_VALID])

    assert cbapi_mock._last_request_data is not None
    assert ENGINE_NAME in cbapi_mock._last_request_data["title"]
    assert cbapi_mock._last_request_data["description"] == "Automated report generated by Binary Analysis SDK"
    assert cbapi_mock._last_request_data["severity"] == IOCS_2[0]["severity"]
    assert cbapi_mock._last_request_data["iocs_v2"] == minus_severity(IOCS_2)
    assert METADATA_VALID["sha256"] in components["state_manager"].get_previous_hashes(ENGINE_NAME)


def test_analyze_command(cbapi_mock, config):
    """Test data flow through the components in the _analyze_command method"""
    sut = AnalysisUtility(None)
    sut.config = config
    sut.cbapi = cbapi_mock.api
    hash = METADATA_VALID["sha256"]
    cbapi_mock.mock_request("POST", f"/ubs/v1/orgs/test/file/_download",
                            {"found": [{"sha256": hash, "url": "DUMMY_URL"}], "not_found": [], "error": []})
    cbapi_mock.mock_request("GET", f"/ubs/v1/orgs/test/sha256/{hash}/metadata", METADATA_VALID)
    cbapi_mock.mock_request("PUT", f"/threathunter/feedmgr/v2/orgs/test/feeds/{FEED_ID}/reports/.*", None)

    components = sut._init_components()
    components["engine_manager"].engine.mock_engine_output(hash, IOCS_2)

    args = Namespace()
    args.file = None
    args.list = json.dumps([hash])
    sut._analyze_command(args, components)

    assert cbapi_mock._last_request_data is not None
    assert ENGINE_NAME in cbapi_mock._last_request_data["title"]
    assert cbapi_mock._last_request_data["description"] == "Automated report generated by Binary Analysis SDK"
    assert cbapi_mock._last_request_data["severity"] == IOCS_2[0]["severity"]
    assert cbapi_mock._last_request_data["iocs_v2"] == minus_severity(IOCS_2)
    assert METADATA_VALID["sha256"] in components["state_manager"].get_previous_hashes(ENGINE_NAME)


def test_analyze_command_with_not_found(cbapi_mock, config):
    """Test data flow through the components in the _analyze_command method for when a hash is not found"""
    sut = AnalysisUtility(None)
    sut.config = config
    sut.cbapi = cbapi_mock.api
    hash = METADATA_VALID["sha256"]
    cbapi_mock.mock_request("POST", f"/ubs/v1/orgs/test/file/_download",
                            {"found": [], "not_found": [hash], "error": []})

    components = sut._init_components()

    args = Namespace()
    args.file = None
    args.list = json.dumps([hash])
    sut._analyze_command(args, components)

    assert cbapi_mock._last_request_data is not None
    ensure_not_report(cbapi_mock._last_request_data)
    assert METADATA_VALID["sha256"] not in components["state_manager"].get_previous_hashes(ENGINE_NAME)


def test_analyze_command_without_feed(cbapi_mock, config3):
    """Test reports are not sent when a feed id is not present"""
    sut = AnalysisUtility(None)
    sut.config = config3
    sut.cbapi = cbapi_mock.api
    hash = METADATA_VALID["sha256"]
    cbapi_mock.mock_request("POST", f"/ubs/v1/orgs/test/file/_download",
                            {"found": [{"sha256": hash, "url": "DUMMY_URL"}], "not_found": [], "error": []})
    cbapi_mock.mock_request("GET", f"/ubs/v1/orgs/test/sha256/{hash}/metadata", METADATA_VALID)

    components = sut._init_components()
    components["engine_manager"].engine.mock_engine_output(hash, IOCS_2)

    args = Namespace()
    args.file = None
    args.list = json.dumps([hash])
    sut._analyze_command(args, components)

    assert cbapi_mock._last_request_data == {
        'expiration_seconds': 3600,
        'sha256': ['0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc']
    } or cbapi_mock._last_request_data is None
    assert METADATA_VALID["sha256"] in components["state_manager"].get_previous_hashes(ENGINE_NAME)


def test_restart_command(cbapi_mock, config):
    """Test data flow through the components in the _restart_command method"""
    sut = AnalysisUtility(None)
    sut.config = config
    sut.cbapi = cbapi_mock.api
    hash = METADATA_VALID["sha256"]
    cbapi_mock.mock_request("POST", f"/ubs/v1/orgs/test/file/_download",
                            {"found": [{"sha256": hash, "url": "DUMMY_URL"}], "not_found": [], "error": []})
    cbapi_mock.mock_request("GET", f"/ubs/v1/orgs/test/sha256/{hash}/metadata", METADATA_VALID)
    cbapi_mock.mock_request("PUT", f"/threathunter/feedmgr/v2/orgs/test/feeds/{FEED_ID}/reports/.*", None)

    components = sut._init_components()
    components["engine_manager"].engine.mock_engine_output(hash, IOCS_2)
    components["state_manager"].set_checkpoint(hash, ENGINE_NAME, "INGESTED")

    sut._restart_command(components)

    assert cbapi_mock._last_request_data is not None
    assert ENGINE_NAME in cbapi_mock._last_request_data["title"]
    assert cbapi_mock._last_request_data["description"] == "Automated report generated by Binary Analysis SDK"
    assert cbapi_mock._last_request_data["severity"] == IOCS_2[0]["severity"]
    assert cbapi_mock._last_request_data["iocs_v2"] == minus_severity(IOCS_2)
    assert METADATA_VALID["sha256"] in components["state_manager"].get_previous_hashes(ENGINE_NAME)


def test_restart_command_with_nothing_to_do(cbapi_mock, config2):
    """Test data flow through the components in the _restart_command when there are no hashes that are incomplete"""
    sut = AnalysisUtility(None)
    sut.config = config2
    sut.cbapi = cbapi_mock.api
    hash = METADATA_VALID["sha256"]

    components = sut._init_components()
    my_timestamp = datetime.now() - timedelta(0, 300)
    components["state_manager"].set_checkpoint(hash, ENGINE_NAME, "DONE", my_timestamp)

    sut._restart_command(components)

    assert cbapi_mock._last_request_data is None
    assert components["state_manager"]._persistor.db[hash]["checkpoint_time"] == my_timestamp


def test_restart_command_with_unsent_report_item(cbapi_mock, config):
    """Test that an unsent report item is sent as a process of running the restart command."""
    sut = AnalysisUtility(None)
    sut.config = config
    sut.cbapi = cbapi_mock.api
    cbapi_mock.mock_request("PUT", f"/threathunter/feedmgr/v2/orgs/test/feeds/{FEED_ID}/reports/.*", None)

    components = sut._init_components()
    components["state_manager"].add_report_item(IOCS_2[0]["severity"], ENGINE_NAME, minus_severity(IOCS_2)[0])
    components["state_manager"].set_checkpoint(METADATA_VALID["sha256"], ENGINE_NAME, "DONE")

    sut._restart_command(components)
    assert cbapi_mock._last_request_data is not None
    assert ENGINE_NAME in cbapi_mock._last_request_data["title"]
    assert cbapi_mock._last_request_data["description"] == "Automated report generated by Binary Analysis SDK"
    assert cbapi_mock._last_request_data["severity"] == IOCS_2[0]["severity"]
    assert cbapi_mock._last_request_data["iocs_v2"] == minus_severity(IOCS_2)
