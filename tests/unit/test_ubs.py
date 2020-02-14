
"""Unit tests for input functions"""

import pytest
from cb_binary_analysis.ubs import (_download_hashes,
                                    _download_binary_metadata,
                                    _validate_download, download_hashes,
                                    get_metadata, RedownloadHashes)
# from cb_binary_analysis.config.model import Config
from cbapi.psc.threathunter import CbThreatHunterAPI
from tests.unit.ubs_fixtures.metadata import metadata_valid
from utils.CBAPIMock import CBAPIMock
from tests.unit.ubs_fixtures.filedownload import FILEDOWNLOADRESP, METADATADOWNLOADRESP


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
    cbapi_mock.mock_request("POST", "/ubs/v1/orgs/test/file/_download", FILEDOWNLOADRESP)
    hash_dl = _download_hashes(cbapi_mock.api, hashes, 60)
    assert len(hash_dl.found) == 1
    assert len(hash_dl.not_found) == 1
    assert len(hash_dl.error) == 0


def test_download_hashes_invalid(cbapi_mock):
    cbapi_mock.mock_request("POST", "/ubs/v1/orgs/test/file/_download", None)
    found_hashes = download_hashes(cbapi_mock.api, [])
    assert found_hashes is None


@pytest.mark.parametrize("hashes", [
    hashes]
)
def test_download_binary_metadata(cbapi_mock, hashes):
    # th = create_cbth_object(config_data._data['carbonblackcloud'])
    cbapi_mock.mock_request("POST", "/ubs/v1/orgs/test/file/_download", FILEDOWNLOADRESP)
    hash_dl = _download_hashes(cbapi_mock.api, hashes, 60)
    found_hashes, redownload_found_hashes = _validate_download(cbapi_mock.api, hash_dl, 60)
    cbapi_mock.mock_request("GET", f"/ubs/v1/orgs/test/sha256/{found_hashes[0]['sha256']}/metadata",
                            METADATADOWNLOADRESP)
    metadata = _download_binary_metadata(cbapi_mock.api, found_hashes[0])
    assert type(metadata) == dict
    for key in metadata_valid.keys():
        assert key in metadata
    for key in metadata.keys():
        assert key in metadata_valid


@pytest.mark.parametrize("hashes", [
    not_found_hashes]
)
def test_download_binary_metadata_not_found(cbapi_mock, hashes):
    with pytest.raises(Exception):
        cbapi_mock.mock_request("POST", "/ubs/v1/orgs/test/file/_download", Exception)  # put in the Exception
        hash_dl = _download_hashes(cbapi_mock.api, hashes, 60)
        assert hash_dl is None
        print(f"hash_dl._info: {hash_dl._info}. type(hash_dl): {type(hash_dl)}")
        check_hash_dl, retry = _validate_download(cbapi_mock.api, hash_dl, 60)
        with pytest.raises(ValueError):
            try_meta = _download_binary_metadata(cbapi_mock.api, check_hash_dl)
            assert try_meta is None
        assert hash_dl is None
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
    if isinstance(input, dict):
        with pytest.raises(KeyError):
            _download_binary_metadata(cbapi_mock.api, input)
    else:
        with pytest.raises(ValueError):
            assert _download_binary_metadata(cbapi_mock.api, input) is None


@pytest.mark.parametrize("hashes", [
    hashes]
)
def test_redownloadHashes(cbapi_mock, hashes):
    cbapi_mock.mock_request("POST", "/ubs/v1/orgs/test/file/_download", FILEDOWNLOADRESP)
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
    cbapi_mock.mock_request("POST", "/ubs/v1/orgs/test/file/_download", FILEDOWNLOADRESP)
    hash_dl = _download_hashes(cbapi_mock.api, hashes, 60)
    found_hashes, redownload_found_hashes = _validate_download(cbapi_mock.api, hash_dl, 60)
    assert len(found_hashes) == 1
    assert redownload_found_hashes is None


@pytest.mark.parametrize("hashes", [
    not_found_hashes]
)
def test_validate_download_not_found(cbapi_mock, hashes):
    with pytest.raises(Exception):
        cbapi_mock.mock_request("POST", "/ubs/v1/orgs/test/file/_download", Exception)
        hash_dl = _download_hashes(cbapi_mock.api, hashes, 60)
        check_hash_dl, retry = _validate_download(cbapi_mock.api, hash_dl, 60)
        assert check_hash_dl is None
        assert retry is None


@pytest.mark.parametrize("hashes", [
    hashes]
)
def test_download_metadata(cbapi_mock, hashes):
    cbapi_mock.mock_request("POST", "/ubs/v1/orgs/test/file/_download", FILEDOWNLOADRESP)
    found_hashes = download_hashes(cbapi_mock.api, hashes)
    cbapi_mock.mock_request("GET", f"/ubs/v1/orgs/test/sha256/{found_hashes[0]['sha256']}/metadata",
                            METADATADOWNLOADRESP)
    metadata = _download_binary_metadata(cbapi_mock.api, found_hashes[0])
    assert isinstance(metadata, dict)
    for key in metadata_valid.keys():
        assert key in metadata
    for key in metadata.keys():
        assert key in metadata_valid


@pytest.mark.parametrize("hashes", [
    hashes]
)
def test_get_metadata(cbapi_mock, hashes):
    cbapi_mock.mock_request("POST", "/ubs/v1/orgs/test/file/_download", FILEDOWNLOADRESP)
    found_hashes = download_hashes(cbapi_mock.api, hashes)
    cbapi_mock.mock_request("GET", f"/ubs/v1/orgs/test/sha256/{found_hashes[0]['sha256']}/metadata",
                            METADATADOWNLOADRESP)
    metadata = get_metadata(cbapi_mock.api, found_hashes[0])
    assert isinstance(metadata, dict)
    for key in metadata_valid.keys():
        assert key in metadata
    for key in metadata.keys():
        assert key in metadata_valid


def test_get_metadata_invalid(cbapi_mock):
    found_hashes = {"something": "wedontwant"}
    with pytest.raises(KeyError):
        get_metadata(cbapi_mock.api, found_hashes)
    empty_dict = {}
    metadata = get_metadata(cbapi_mock.api, empty_dict)
    assert metadata is None
