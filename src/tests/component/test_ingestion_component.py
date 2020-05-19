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

"""Unit tests for the ingestion actor"""

import pytest

from cbc_binary_toolkit.ingestion_component import IngestionComponent
from cbc_binary_toolkit.state import StateManager
from cbc_binary_toolkit.config import Config
from cbapi.psc.threathunter import CbThreatHunterAPI
from tests.component.ubs_fixtures.CBAPIMock import CBAPIMock
from tests.component.ubs_fixtures.metadata import HASH_METADATA
from tests.component.ubs_fixtures.filedownload import METADATA_DOWNLOAD_RESP

ENGINE_NAME = "TEST_ENGINE"


@pytest.fixture(scope="session")
def config():
    """Configuration for all the test cases in this module."""
    return Config.load(f"""
    id: cbc_binary_toolkit
    version: 0.0.1
    carbonblackcloud:
      expiration_seconds: 3600
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
def component(config, cb_threat_hunter, state_manager):
    """Creates the component to unit test"""
    return IngestionComponent(config, cb_threat_hunter, state_manager)


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

    cbapi_mock.mock_request("POST", "/ubs/v1/orgs/test/file/_download", mock_downloads)
    return cbapi_mock


# ==================================== Unit TESTS BELOW ====================================


@pytest.mark.parametrize("input", [
    # Single hash in a single batch
    ['405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4'],
    # Multiple hashes in a single batch
    ['405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4',
     '0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc']
])
def test_fetch_metadata(component, cbapi_mock, state_manager, input):
    """Test fetch metadata"""
    data = component.fetch_metadata(input)
    assert data != []
    for item in data:
        assert item == METADATA_DOWNLOAD_RESP[item["sha256"]]


@pytest.mark.parametrize("input", [
    # Hash metadata missing
    ['e02d9989cbe295518350ed3f5a04a713ece692406a9ee354785c2a4078466dcd'],
    # Hash not found in UBS
    ['31132832bc0f3ce4a15601dc190c98b9a40a9aba1d87dae59b217610175bdfde'],
    # Invalid hash
    ['INVALID']
])
def test_hash_not_found(component, cbapi_mock, state_manager, input):
    """Test fetch_metadata with various failure points"""
    data = component.fetch_metadata(input)
    assert data == []


def test_reload(component, cbapi_mock, state_manager):
    """Test restart command"""
    state_manager.set_checkpoint("405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4",
                                 ENGINE_NAME,
                                 "INGESTED")
    state_manager.set_checkpoint("0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc",
                                 ENGINE_NAME,
                                 "DONE")

    data = component.reload()

    assert data[0] == METADATA_DOWNLOAD_RESP["405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4"]
