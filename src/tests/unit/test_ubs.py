
"""Unit tests for input functions"""

import pytest
from cbc_binary_toolkit.ubs import (_download_hashes,
                                _download_binary_metadata,
                                _validate_download,
                                download_hashes,
                                get_metadata,
                                RedownloadHashes)
from cbapi.psc.threathunter import CbThreatHunterAPI
from tests.unit.ubs_fixtures.metadata import METADATA_VALID
from tests.unit.ubs_fixtures.CBAPIMock import CBAPIMock
from tests.unit.ubs_fixtures.filedownload import (FILE_DOWNLOAD_RESP, METADATA_DOWNLOAD_RESP,
                                                  FILE_DOWNLOAD_ERROR, FILE_DOWNLOAD_ALL)


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


hashes = ["6c4eb3c9e0f478b2d19a329687d113ba92c90a17d0caa6c40247a5afff31f0cd",
          "0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc"]
not_found_hashes = ["6c4eb3c9e0f478b2d19a329687d113ba92c90a17d0caa6c40247a5afff31f0cd"]


@pytest.mark.parametrize("hashes", [
    hashes]
)
def test_download_hashes(cbapi_mock, hashes):
    """Unit test _download_hashes function."""
    cbapi_mock.mock_request("POST", "/ubs/v1/orgs/test/file/_download", FILE_DOWNLOAD_RESP)
    hash_dl = _download_hashes(cbapi_mock.api, hashes, 60)
    assert len(hash_dl.found) == 1
    assert len(hash_dl.not_found) == 1
    assert len(hash_dl.error) == 0


def test_download_hashes_invalid(cbapi_mock):
    """Unit test _download_hashes function with empty input."""
    cbapi_mock.mock_request("POST", "/ubs/v1/orgs/test/file/_download", None)
    found_hashes = download_hashes(cbapi_mock.api, [])
    assert found_hashes is None


@pytest.mark.parametrize("hashes", [
    hashes,
    not_found_hashes]
)
def test_download_hashes_exception(cbapi_mock, hashes):
    """Unit test _download_hashes function when an Exception is thrown."""
    with pytest.raises(Exception):
        cbapi_mock.mock_request("POST", "/ubs/v1/orgs/test/file/_download", Exception)
        dl = _download_hashes(cbapi_mock.api, hashes, 60)
        assert dl is None


@pytest.mark.parametrize("hashes", [
    hashes]
)
def test_download_binary_metadata(cbapi_mock, hashes):
    """Unit test _download_binary_metadata function."""
    cbapi_mock.mock_request("POST", "/ubs/v1/orgs/test/file/_download", FILE_DOWNLOAD_RESP)
    hash_dl = _download_hashes(cbapi_mock.api, hashes, 60)
    found_hashes, redownload_found_hashes = _validate_download(cbapi_mock.api, hash_dl, 60)
    cbapi_mock.mock_request("GET", f"/ubs/v1/orgs/test/sha256/{found_hashes[0]['sha256']}/metadata",
                            METADATA_DOWNLOAD_RESP[found_hashes[0]['sha256']])
    metadata = _download_binary_metadata(cbapi_mock.api, found_hashes[0])
    assert type(metadata) == dict
    for key in METADATA_VALID.keys():
        assert key in metadata
    for key in metadata.keys():
        assert key in METADATA_VALID


@pytest.mark.parametrize("hashes", [
    not_found_hashes]
)
def test_download_binary_metadata_not_found(cbapi_mock, hashes):
    """Unit test _download_binary_metadata function with hashes not in UBS."""
    with pytest.raises(Exception):
        cbapi_mock.mock_request("POST", "/ubs/v1/orgs/test/file/_download", Exception)  # put in the Exception
        hash_dl = _download_hashes(cbapi_mock.api, hashes, 60)
        assert hash_dl is None
        check_hash_dl, retry = _validate_download(cbapi_mock.api, hash_dl, 60)
        with pytest.raises(ValueError):
            try_meta = _download_binary_metadata(cbapi_mock.api, check_hash_dl)
            assert try_meta is None
        assert check_hash_dl is None
        assert retry is None


@pytest.mark.parametrize("input", [
    {"not": "something"},
    {"url": "missingthesha256key"},
    {"sha256": "missingtheurlkey"},
    True,
    None,
    ["alist"],
    ["url", "sha256"]]
)
def test_download_binary_metadata_invalid(cbapi_mock, input):
    """Unit test _download_binary_metadata function for invalid inputs."""
    if isinstance(input, dict):
        with pytest.raises(KeyError):
            metadl = _download_binary_metadata(cbapi_mock.api, input)
            assert metadl is None
    else:
        with pytest.raises(ValueError):
            assert _download_binary_metadata(cbapi_mock.api, input) is None


@pytest.mark.parametrize("hashes", [
    hashes]
)
def test_redownloadHashes(cbapi_mock, hashes):
    """Unit test RedownloadHashes class and function."""
    cbapi_mock.mock_request("POST", "/ubs/v1/orgs/test/file/_download", FILE_DOWNLOAD_RESP)
    redownload = RedownloadHashes(cbapi_mock.api, hashes, 60)
    assert redownload.cb == cbapi_mock.api
    assert redownload.shas == hashes
    assert redownload.expiration_seconds == 60
    assert redownload.found == []
    redownload.redownload()
    assert len(redownload.found) == 1


@pytest.mark.parametrize("hashes", [
    hashes]
)
def test_validate_download(cbapi_mock, hashes):
    """Unit test _validate_download function."""
    cbapi_mock.mock_request("POST", "/ubs/v1/orgs/test/file/_download", FILE_DOWNLOAD_RESP)
    hash_dl = _download_hashes(cbapi_mock.api, hashes, 60)
    found_hashes, redownload_found_hashes = _validate_download(cbapi_mock.api, hash_dl, 60)
    assert len(found_hashes) == 1
    assert redownload_found_hashes is None


@pytest.mark.parametrize("hashes", [
    not_found_hashes]
)
def test_validate_download_not_found(cbapi_mock, hashes):
    """Unit test _validate_download function with hashes not in UBS."""
    with pytest.raises(Exception):
        cbapi_mock.mock_request("POST", "/ubs/v1/orgs/test/file/_download", Exception)
        hash_dl = _download_hashes(cbapi_mock.api, hashes, 60)
        check_hash_dl, retry = _validate_download(cbapi_mock.api, hash_dl, 60)
        assert check_hash_dl is None
        assert retry is None


def test_validate_download_empty(cbapi_mock):
    """Unit test _validate_download function with empty input."""
    assert _validate_download(cbapi_mock.api, None, 60) == (None, None)


@pytest.mark.parametrize("hashes", [
    hashes]
)
def test_download_metadata(cbapi_mock, hashes):
    """Unit test download_hashes function."""
    cbapi_mock.mock_request("POST", "/ubs/v1/orgs/test/file/_download", FILE_DOWNLOAD_RESP)
    found_hashes = download_hashes(cbapi_mock.api, hashes)
    cbapi_mock.mock_request("GET", f"/ubs/v1/orgs/test/sha256/{found_hashes[0]['sha256']}/metadata",
                            METADATA_DOWNLOAD_RESP[found_hashes[0]['sha256']])
    metadata = _download_binary_metadata(cbapi_mock.api, found_hashes[0])
    assert isinstance(metadata, dict)
    for key in METADATA_VALID.keys():
        assert key in metadata
    for key in metadata.keys():
        assert key in METADATA_VALID


@pytest.mark.parametrize("hashes", [
    hashes]
)
def test_get_metadata(cbapi_mock, hashes):
    """Unit test get_metadata function."""
    cbapi_mock.mock_request("POST", "/ubs/v1/orgs/test/file/_download", FILE_DOWNLOAD_RESP)
    found_hashes = download_hashes(cbapi_mock.api, hashes)
    cbapi_mock.mock_request("GET", f"/ubs/v1/orgs/test/sha256/{found_hashes[0]['sha256']}/metadata",
                            METADATA_DOWNLOAD_RESP[found_hashes[0]['sha256']])
    metadata = get_metadata(cbapi_mock.api, found_hashes[0])
    assert isinstance(metadata, dict)
    for key in METADATA_VALID.keys():
        assert key in metadata
    for key in metadata.keys():
        assert key in METADATA_VALID


def test_get_metadata_invalid(cbapi_mock):
    """Unit test get_metadata function with empty input."""
    found_hashes = {"something": "wedontwant"}
    with pytest.raises(KeyError):
        get_metadata(cbapi_mock.api, found_hashes)
    empty_dict = {}
    metadata = get_metadata(cbapi_mock.api, empty_dict)
    assert metadata is None


@pytest.mark.parametrize("hashes", [
    hashes,
    not_found_hashes]
)
def test_redownload_class_only_errors(cbapi_mock, hashes):
    """Unit test RedownloadHashes function with mock error response."""
    redownload = RedownloadHashes(cbapi_mock.api, hashes, 60)
    cbapi_mock.mock_request("POST", "/ubs/v1/orgs/test/file/_download", FILE_DOWNLOAD_ERROR)
    redownload.redownload()
    assert len(redownload.found) == 0


@pytest.mark.parametrize("hashes", [
    hashes,
    not_found_hashes]
)
def test_redownload_class_found_notfound(cbapi_mock, hashes):
    """Unit test RedownloadHashes function with mock found and not_found response."""
    redownload = RedownloadHashes(cbapi_mock.api, hashes, 60)
    cbapi_mock.mock_request("POST", "/ubs/v1/orgs/test/file/_download", FILE_DOWNLOAD_RESP)
    redownload.redownload()
    assert len(redownload.found) == 1


@pytest.mark.parametrize("hashes", [
    hashes]
)
def test_redownload_class_all_types(cbapi_mock, hashes):
    """Unit test RedownloadHashes function with mock found, not_found, and error response."""
    redownload = RedownloadHashes(cbapi_mock.api, hashes, 60)
    assert redownload.shas == hashes
    assert len(redownload.found) == 0
    cbapi_mock.mock_request("POST", "/ubs/v1/orgs/test/file/_download", FILE_DOWNLOAD_ALL)
    redownload.redownload()
    assert len(redownload.found) == 16
    assert redownload.attempt_num == 5
