# -*- coding: utf-8 -*-

# *******************************************************
# Copyright (c) VMware, Inc. 2020-2021. All Rights Reserved.
# SPDX-License-Identifier: MIT
# *******************************************************
# *
# * DISCLAIMER. THIS PROGRAM IS PROVIDED TO YOU "AS IS" WITHOUT
# * WARRANTIES OR CONDITIONS OF ANY KIND, WHETHER ORAL OR WRITTEN,
# * EXPRESS OR IMPLIED. THE AUTHOR SPECIFICALLY DISCLAIMS ANY IMPLIED
# * WARRANTIES OR CONDITIONS OF MERCHANTABILITY, SATISFACTORY QUALITY,
# * NON-INFRINGEMENT AND FITNESS FOR A PARTICULAR PURPOSE.

"""Unit tests for input functions"""

import pytest
from cbc_binary_toolkit.ubs import (_download_hashes,
                                    _download_binary_metadata,
                                    _validate_download,
                                    download_hashes,
                                    get_metadata,
                                    RedownloadHashes)
from cbc_sdk import CBCloudAPI
from tests.component.ubs_fixtures.metadata import METADATA_VALID
from tests.component.ubs_fixtures.CBCloudAPIMock import CBCloudAPIMock
from tests.component.ubs_fixtures.filedownload import (FILE_DOWNLOAD_RESP,
                                                       METADATA_DOWNLOAD_RESP,
                                                       FILE_DOWNLOAD_ERROR,
                                                       FILE_DOWNLOAD_ALL)


@pytest.fixture(scope="session")
def cbc_cloud_api():
    """Create CBCloudAPI singleton"""
    return CBCloudAPI(url="https://example.com",
                      org_key="test",
                      token="abcd/1234",
                      ssl_verify=False)


@pytest.fixture(scope="function")
def cbcloud_api_mock(monkeypatch, cbc_cloud_api):
    """Mocks CBCloudAPI for unit tests"""
    return CBCloudAPIMock(monkeypatch, cbc_cloud_api)


hashes = ["6c4eb3c9e0f478b2d19a329687d113ba92c90a17d0caa6c40247a5afff31f0cd",
          "0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc"]
not_found_hashes = ["6c4eb3c9e0f478b2d19a329687d113ba92c90a17d0caa6c40247a5afff31f0cd"]


# ==================================== UNIT TESTS BELOW ====================================


@pytest.mark.parametrize("input", [
    {"not": "something"},
    {"url": "missingthesha256key"},
    {"sha256": "missingtheurlkey"},
    True,
    None,
    ["alist"],
    ["url", "sha256"]]
)
def test_download_binary_metadata_invalid(cbcloud_api_mock, input):
    """Unit test _download_binary_metadata function for invalid inputs."""
    assert _download_binary_metadata(cbcloud_api_mock.api, input) == {}


def test_validate_download_empty(cbcloud_api_mock):
    """Unit test _validate_download function with empty input."""
    assert _validate_download(cbcloud_api_mock.api, None, 60) == (None, None)


@pytest.mark.parametrize("found_hashes", [
    {"something": "wedontwant"},
    {},
    None,
    "invalid",
    0,
    {"sha256": "some_hash", "url": None}]
)
def test_get_metadata_invalid(cbcloud_api_mock, found_hashes):
    """Unit test get_metadata function with empty input."""
    assert get_metadata(cbcloud_api_mock.api, found_hashes) == {}


# ==================================== INTEGRATION TESTS BELOW ====================================


@pytest.mark.parametrize("hashes", [
    hashes]
)
def test_download_hashes(cbcloud_api_mock, hashes):
    """Unit test _download_hashes function."""
    cbcloud_api_mock.mock_request("POST", "/ubs/v1/orgs/test/file/_download", FILE_DOWNLOAD_RESP)
    hash_dl = _download_hashes(cbcloud_api_mock.api, hashes, 60)
    assert len(hash_dl.found) == 1
    assert len(hash_dl.not_found) == 1
    assert len(hash_dl.error) == 0


@pytest.mark.parametrize("input", [
    [],
    None,
    (),
    0
])
def test_download_hashes_invalid(cbcloud_api_mock, input):
    """Unit test _download_hashes function with empty input."""
    cbcloud_api_mock.mock_request("POST", "/ubs/v1/orgs/test/file/_download", None)
    found_hashes = download_hashes(cbcloud_api_mock.api, input)
    assert found_hashes == []


@pytest.mark.parametrize("hashes", [
    hashes,
    not_found_hashes]
)
def test_download_hashes_exception(cbcloud_api_mock, hashes):
    """Unit test _download_hashes function when an Exception is thrown."""
    with pytest.raises(Exception):
        cbcloud_api_mock.mock_request("POST", "/ubs/v1/orgs/test/file/_download", Exception)
        dl = _download_hashes(cbcloud_api_mock.api, hashes, 60)
        assert dl is None


@pytest.mark.parametrize("hashes", [
    hashes]
)
def test_download_binary_metadata(cbcloud_api_mock, hashes):
    """Unit test _download_binary_metadata function."""
    cbcloud_api_mock.mock_request("POST", "/ubs/v1/orgs/test/file/_download", FILE_DOWNLOAD_RESP)
    hash_dl = _download_hashes(cbcloud_api_mock.api, hashes, 60)
    found_hashes, redownload_found_hashes = _validate_download(cbcloud_api_mock.api, hash_dl, 60)
    cbcloud_api_mock.mock_request("GET", f"/ubs/v1/orgs/test/sha256/{found_hashes[0]['sha256']}/metadata",
                                  METADATA_DOWNLOAD_RESP[found_hashes[0]['sha256']])
    metadata = _download_binary_metadata(cbcloud_api_mock.api, found_hashes[0])
    assert type(metadata) == dict
    for key in METADATA_VALID.keys():
        assert key in metadata
    for key in metadata.keys():
        assert key in METADATA_VALID


@pytest.mark.parametrize("hashes", [
    not_found_hashes]
)
def test_download_binary_metadata_not_found(cbcloud_api_mock, hashes):
    """Unit test _download_binary_metadata function with hashes not in UBS."""
    with pytest.raises(Exception):
        cbcloud_api_mock.mock_request("POST", "/ubs/v1/orgs/test/file/_download", Exception)  # put in the Exception
        hash_dl = _download_hashes(cbcloud_api_mock.api, hashes, 60)
        assert hash_dl is None
        check_hash_dl, retry = _validate_download(cbcloud_api_mock.api, hash_dl, 60)
        with pytest.raises(ValueError):
            try_meta = _download_binary_metadata(cbcloud_api_mock.api, check_hash_dl)
            assert try_meta is None
        assert check_hash_dl is None
        assert retry is None


@pytest.mark.parametrize("hashes", [
    hashes]
)
def test_redownloadHashes(cbcloud_api_mock, hashes):
    """Unit test RedownloadHashes class and function."""
    cbcloud_api_mock.mock_request("POST", "/ubs/v1/orgs/test/file/_download", FILE_DOWNLOAD_RESP)
    redownload = RedownloadHashes(cbcloud_api_mock.api, hashes, 60)
    assert redownload.cbc_api == cbcloud_api_mock.api
    assert redownload.shas == hashes
    assert redownload.expiration_seconds == 60
    assert redownload.found == []
    redownload.redownload()
    assert len(redownload.found) == 1


@pytest.mark.parametrize("hashes", [
    hashes]
)
def test_validate_download(cbcloud_api_mock, hashes):
    """Unit test _validate_download function."""
    cbcloud_api_mock.mock_request("POST", "/ubs/v1/orgs/test/file/_download", FILE_DOWNLOAD_RESP)
    hash_dl = _download_hashes(cbcloud_api_mock.api, hashes, 60)
    found_hashes, redownload_found_hashes = _validate_download(cbcloud_api_mock.api, hash_dl, 60)
    assert len(found_hashes) == 1
    assert redownload_found_hashes is None


@pytest.mark.parametrize("hashes", [
    not_found_hashes]
)
def test_validate_download_not_found(cbcloud_api_mock, hashes):
    """Unit test _validate_download function with hashes not in UBS."""
    with pytest.raises(Exception):
        cbcloud_api_mock.mock_request("POST", "/ubs/v1/orgs/test/file/_download", Exception)
        hash_dl = _download_hashes(cbcloud_api_mock.api, hashes, 60)
        check_hash_dl, retry = _validate_download(cbcloud_api_mock.api, hash_dl, 60)
        assert check_hash_dl is None
        assert retry is None


@pytest.mark.parametrize("hashes", [
    hashes]
)
def test_download_metadata(cbcloud_api_mock, hashes):
    """Unit test download_hashes function."""
    cbcloud_api_mock.mock_request("POST", "/ubs/v1/orgs/test/file/_download", FILE_DOWNLOAD_RESP)
    found_hashes = download_hashes(cbcloud_api_mock.api, hashes)
    cbcloud_api_mock.mock_request("GET", f"/ubs/v1/orgs/test/sha256/{found_hashes[0]['sha256']}/metadata",
                                  METADATA_DOWNLOAD_RESP[found_hashes[0]['sha256']])
    metadata = _download_binary_metadata(cbcloud_api_mock.api, found_hashes[0])
    assert isinstance(metadata, dict)
    for key in METADATA_VALID.keys():
        assert key in metadata
    for key in metadata.keys():
        assert key in METADATA_VALID


@pytest.mark.parametrize("hashes", [
    hashes]
)
def test_get_metadata(cbcloud_api_mock, hashes):
    """Unit test get_metadata function."""
    cbcloud_api_mock.mock_request("POST", "/ubs/v1/orgs/test/file/_download", FILE_DOWNLOAD_RESP)
    found_hashes = download_hashes(cbcloud_api_mock.api, hashes)
    cbcloud_api_mock.mock_request("GET", f"/ubs/v1/orgs/test/sha256/{found_hashes[0]['sha256']}/metadata",
                                  METADATA_DOWNLOAD_RESP[found_hashes[0]['sha256']])
    metadata = get_metadata(cbcloud_api_mock.api, found_hashes[0])
    assert isinstance(metadata, dict)
    for key in METADATA_VALID.keys():
        assert key in metadata
    for key in metadata.keys():
        assert key in METADATA_VALID


@pytest.mark.parametrize("hashes", [
    hashes,
    not_found_hashes]
)
def test_redownload_class_only_errors(cbcloud_api_mock, hashes):
    """Unit test RedownloadHashes function with mock error response."""
    redownload = RedownloadHashes(cbcloud_api_mock.api, hashes, 60)
    cbcloud_api_mock.mock_request("POST", "/ubs/v1/orgs/test/file/_download", FILE_DOWNLOAD_ERROR)
    redownload.redownload()
    assert len(redownload.found) == 0
    assert len(redownload.not_found) == 0


@pytest.mark.parametrize("hashes", [
    hashes,
    not_found_hashes]
)
def test_redownload_class_found_notfound(cbcloud_api_mock, hashes):
    """Unit test RedownloadHashes function with mock found and not_found response."""
    redownload = RedownloadHashes(cbcloud_api_mock.api, hashes, 60)
    cbcloud_api_mock.mock_request("POST", "/ubs/v1/orgs/test/file/_download", FILE_DOWNLOAD_RESP)
    redownload.redownload()
    assert len(redownload.found) == 1


@pytest.mark.parametrize("hashes", [
    hashes]
)
def test_redownload_class_all_types(cbcloud_api_mock, hashes):
    """Unit test RedownloadHashes function with mock found, not_found, and error response."""
    redownload = RedownloadHashes(cbcloud_api_mock.api, hashes, 60)
    assert redownload.shas == hashes
    assert len(redownload.found) == 0
    cbcloud_api_mock.mock_request("POST", "/ubs/v1/orgs/test/file/_download", FILE_DOWNLOAD_ALL)
    redownload.redownload()
    assert len(redownload.found) == 5
    assert len(redownload.not_found) == 5
    assert redownload.attempt_num == 5
