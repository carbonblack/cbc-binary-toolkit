# -*- coding: utf-8 -*-

"""Integration tests between the components"""

import pytest

from cbapi.psc.threathunter import CbThreatHunterAPI

from cbc_binary_toolkit import DeduplicationComponent, EngineResults, IngestionComponent
from cbc_binary_toolkit.cli_input import read_json
from cbc_binary_toolkit.config import Config
from cbc_binary_toolkit.engine import LocalEngineManager
from cbc_binary_toolkit.state import StateManager
from cbc_binary_toolkit.schemas import BinaryMetadataSchema, EngineResponseSchema, IOCv2Schema, ReportSchema

from tests.component.ubs_fixtures.CBAPIMock import CBAPIMock
from tests.component.ubs_fixtures.metadata import HASH_METADATA
from tests.component.ubs_fixtures.filedownload import METADATA_DOWNLOAD_RESP
from tests.component.engine_fixtures.messages import IOC_HASH

ENGINE_NAME = "MockEngine"
FEED_ID = "FEED_ID"
HASH_ALREADY_DONE = "e02d9989cbe295518350ed3f5a04a713ece692406a9ee354785c2a4078466dcd"


@pytest.fixture(scope="session")
def config():
    """Configuration for all the test cases in this module."""
    return Config.load(f"""
    id: cbc_binary_toolkit
    version: 0.0.1
    carbonblackcloud:
      expiration_seconds: 3600
    database:
      _provider: tests.component.persistor_fixtures.mock_persistor.MockPersistorFactory
    engine:
      name: {ENGINE_NAME}
      feed_id: {FEED_ID}
      local: True
      _provider: tests.component.engine_fixtures.mock_engine.MockLocalEngineFactory
    """)


@pytest.fixture(scope="function")
def state_manager(config):
    """Creates state manager for integration tests"""
    manager = StateManager(config)

    manager.set_checkpoint(HASH_ALREADY_DONE,
                           ENGINE_NAME,
                           "DONE")
    return manager


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
    cbapi_mock.mock_request("PUT", f"/threathunter/feedmgr/v2/orgs/test/feeds/{FEED_ID}/reports/.*", None)
    return cbapi_mock


# ==================================== Components ====================================

@pytest.fixture(scope="function")
def deduplication_component(config, state_manager):
    """Creates the deduplication_component to integration test"""
    return DeduplicationComponent(config, state_manager)


@pytest.fixture(scope="function")
def ingestion_component(config, cb_threat_hunter, state_manager):
    """Creates the ingestion_component to integration test"""
    return IngestionComponent(config, cb_threat_hunter, state_manager)


@pytest.fixture(scope="function")
def local_engine_manager(config):
    """Creates local engine manager for integration tests"""
    manager = LocalEngineManager(config)

    manager.engine.mock_engine_output("405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4", IOC_HASH)
    return manager


@pytest.fixture(scope="function")
def engine_results(state_manager, cb_threat_hunter):
    """Create engine results component."""
    return EngineResults(ENGINE_NAME, state_manager, cb_threat_hunter)


# ==================================== TESTS BELOW ====================================

def test_integration_ingest(cbapi_mock, deduplication_component, ingestion_component, state_manager):
    """Test input to ingestion"""
    input = read_json('["31132832bc0f3ce4a15601dc190c98b9a40a9aba1d87dae59b217610175bdfde", \
                        "405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4", \
                        "0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc", \
                        "e02d9989cbe295518350ed3f5a04a713ece692406a9ee354785c2a4078466dcd"]')
    assert isinstance(input, list)

    unique_list = deduplication_component.deduplicate(input)
    assert HASH_ALREADY_DONE not in unique_list

    ingestion_component.fetch_metadata(unique_list)
    db = state_manager._persistor.db
    assert "31132832bc0f3ce4a15601dc190c98b9a40a9aba1d87dae59b217610175bdfde" not in db
    assert db["405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4"]["checkpoint_name"] == "INGESTED"
    assert db["0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc"]["checkpoint_name"] == "INGESTED"
    assert db["e02d9989cbe295518350ed3f5a04a713ece692406a9ee354785c2a4078466dcd"]["checkpoint_name"] == "DONE"


def test_integration_analyze(cbapi_mock, ingestion_component, local_engine_manager):
    """Test ingest to local engine manager"""
    metadata_list = ingestion_component.fetch_metadata([
        "405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4",
        "0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc"])

    for item in metadata_list:
        assert BinaryMetadataSchema.validate(item)
        assert EngineResponseSchema.validate(local_engine_manager.analyze(item))


def test_integration_results(cbapi_mock, local_engine_manager, engine_results, state_manager):
    """Test local engine manager to engine_results"""
    result = local_engine_manager.analyze(
        METADATA_DOWNLOAD_RESP["405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4"])

    engine_results.receive_response(result)
    assert IOCv2Schema.validate(state_manager._persistor.iocs[0][ENGINE_NAME][0])

    engine_results.send_reports(FEED_ID)
    assert ReportSchema.validate(cbapi_mock._last_request_data)
