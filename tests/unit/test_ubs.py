
"""Unit tests for input functions"""

import pytest
from cb_binary_analysis.ubs import (_create_cbth, _download_hashes,
                                    _download_binary_metadata,
                                    _validate_download, download_hashes,
                                    get_metadata, RedownloadHashes)
from cb_binary_analysis.config.model import Config
from cbapi.psc.threathunter import CbThreatHunterAPI
from tests.unit.ubs_fixtures.metadata import metadata_valid
import os

config_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "ubs_fixtures/binary-analysis-config.yaml")
config_data = Config.load_file(config_path)


def create_cbth_object(args):
    """Create CBTH object for use in other tests"""
    return CbThreatHunterAPI(url=args['url'], token=args['apitoken'],
                             ssl_verify=args['ssl_verify'],
                             org_key=args['orgkey'])


hashes = ["6c4eb3c9e0f478b2d19a329687d113ba92c90a17d0caa6c40247a5afff31f0cd",
          "0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc"]
not_found_hashes = ["6c4eb3c9e0f478b2d19a329687d113ba92c90a17d0caa6c40247a5afff31f0cd"]


@pytest.mark.parametrize("args", [
    config_data._data['carbonblackcloud']
])
def test_create_cbth(args):
    """Test creating a CBTH object (excluding the location in memory with [:-13])"""
    assert str(_create_cbth(args))[:60] == "<cbapi.psc.threathunter.rest_api.CbThreatHunterAPI object at"


@pytest.mark.parametrize("args", [
    None
])
def test_create_cbth_invalid(args):
    """Test creating a CBTH object with invalid args"""
    with pytest.raises(TypeError):
        _create_cbth(args)


@pytest.mark.parametrize("hashes", [
    hashes]
)
def test_download_hashes(hashes):
    th = create_cbth_object(config_data._data['carbonblackcloud'])
    hash_dl = _download_hashes(th, hashes, 60)
    assert len(hash_dl.found) == 1
    assert len(hash_dl.not_found) == 1
    assert len(hash_dl.error) == 0


def test_download_hashes_invalid():
    found_hashes = download_hashes(config_data, [])
    assert found_hashes is None


@pytest.mark.parametrize("hashes", [
    hashes]
)
def test_download_binary_metadata(hashes):
    th = create_cbth_object(config_data._data['carbonblackcloud'])
    hash_dl = _download_hashes(th, hashes, 60)
    found_hashes, redownload_found_hashes = _validate_download(th, hash_dl, 60)
    metadata = _download_binary_metadata(th, found_hashes[0])
    assert type(metadata) == dict
    for key in metadata_valid.keys():
        assert key in metadata
    for key in metadata.keys():
        assert key in metadata_valid


@pytest.mark.parametrize("hashes", [
    not_found_hashes]
)
def test_download_binary_metadata_not_found(hashes):
    th = create_cbth_object(config_data._data['carbonblackcloud'])
    hash_dl = _download_hashes(th, hashes, 60)
    check_hash_dl, retry = _validate_download(th, hash_dl, 60)
    with pytest.raises(ValueError):
        try_meta = _download_binary_metadata(th, check_hash_dl)
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
def test_download_binary_metadata_invalid(input):
    th = create_cbth_object(config_data._data['carbonblackcloud'])
    if isinstance(input, dict):
        with pytest.raises(KeyError):
            _download_binary_metadata(th, input)
    else:
        with pytest.raises(ValueError):
            assert _download_binary_metadata(th, input) is None
    # elif isinstance(input, list):
    #     with pytest.raises(TypeError):
    #         _download_binary_metadata(th, input)
    # else:
    #     assert _download_binary_metadata(th, input) is None


@pytest.mark.parametrize("hashes", [
    hashes]
)
def test_redownloadHashes(hashes):
    th = create_cbth_object(config_data._data['carbonblackcloud'])
    redownload = RedownloadHashes(th, hashes, 60)
    assert redownload.cb == th
    assert redownload.shas == hashes
    assert redownload.expiration_seconds == 60
    assert redownload.found == []
    redownload.redownload()
    assert len(redownload.found) == 1


@pytest.mark.parametrize("hashes", [
    hashes]
)
def test_validate_download(hashes):
    th = create_cbth_object(config_data._data['carbonblackcloud'])
    hash_dl = _download_hashes(th, hashes, 60)
    found_hashes, redownload_found_hashes = _validate_download(th, hash_dl, 60)
    assert len(found_hashes) == 1
    assert redownload_found_hashes is None


@pytest.mark.parametrize("hashes", [
    not_found_hashes]
)
def test_validate_download_not_found(hashes):
    th = create_cbth_object(config_data._data['carbonblackcloud'])
    hash_dl = _download_hashes(th, hashes, 60)
    check_hash_dl, retry = _validate_download(th, hash_dl, 60)
    assert check_hash_dl is None
    assert retry is None


@pytest.mark.parametrize("hashes", [
    hashes]
)
def test_download_metadata(hashes):
    th = create_cbth_object(config_data._data['carbonblackcloud'])
    found_hashes = download_hashes(config_data, hashes)
    metadata = _download_binary_metadata(th, found_hashes[0])
    assert isinstance(metadata, dict)
    for key in metadata_valid.keys():
        assert key in metadata
    for key in metadata.keys():
        assert key in metadata_valid


@pytest.mark.parametrize("hashes", [
    hashes]
)
def test_get_metadata(hashes):
    th = create_cbth_object(config_data._data['carbonblackcloud'])
    found_hashes = download_hashes(config_data, hashes)
    metadata = get_metadata(th, found_hashes[0])
    assert isinstance(metadata, dict)
    for key in metadata_valid.keys():
        assert key in metadata
    for key in metadata.keys():
        assert key in metadata_valid


def test_get_metadata_invalid():
    th = create_cbth_object(config_data._data['carbonblackcloud'])
    found_hashes = {"something": "wedontwant"}
    with pytest.raises(KeyError):
        get_metadata(th, found_hashes)
    empty_dict = {}
    metadata = get_metadata(th, empty_dict)
    assert metadata is None
