
"""Unit tests for input functions"""

import pytest
from cb_binary_analysis.ubs import (_create_cbth, _download_hashes,
                                    _download_hash_metadata, _retry_download,
                                    _check_download, download)
from cb_binary_analysis.config.model import Config
from cbapi.psc.threathunter import CbThreatHunterAPI

from tests.unit.ubs_fixtures.metadata import metadata_valid


config_data = Config.load_file('/Users/llyon/reno/dev/cb-binary-analysis/config/binary-analysis-config.yaml')


def create_cbth_object(args):
    """Create CBTH object for use in other tests"""
    return CbThreatHunterAPI(url=args['url'], token=args['apitoken'],
                             ssl_verify=args['ssl_verify'],
                             org_key=args['orgkey'])


hashes = ["6c4eb3c9e0f478b2d19a329687d113ba92c90a17d0caa6c40247a5afff31f0cd", "0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc"]
not_found_hashes = ["6c4eb3c9e0f478b2d19a329687d113ba92c90a17d0caa6c40247a5afff31f0cd"]
# cbth = create_cbth_object(config_data._data['carbonblackcloud'])


@pytest.mark.parametrize("args", [
    config_data._data['carbonblackcloud']
])
def test_create_cbth(args):
    """Test creating a CBTH object (excluding the location in memory with [:-13])"""
    assert str(_create_cbth(args))[:-13] == "<cbapi.psc.threathunter.rest_api.CbThreatHunterAPI object at"


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
    hash_dl = _download_hashes(th, hashes)
    assert len(hash_dl.found) == 1
    assert len(hash_dl.not_found) == 1
    assert len(hash_dl.error) == 0


@pytest.mark.parametrize("hashes", [
    hashes]
)
def test_download_hash_metadata(hashes):
    th = create_cbth_object(config_data._data['carbonblackcloud'])
    hash_dl = _download_hashes(th, hashes)
    check_hash_dl = _check_download(th, hash_dl, attempt_num=1)
    metadata = _download_hash_metadata(th, check_hash_dl.found)
    assert type(metadata[0]) == dict
    assert type(metadata) == list
    for key in metadata_valid.keys():
        assert key in metadata[0]


@pytest.mark.parametrize("hashes", [
    not_found_hashes]
)
def test_download_hash_metadata_invalid(hashes):
    th = create_cbth_object(config_data._data['carbonblackcloud'])
    hash_dl = _download_hashes(th, hashes)
    check_hash_dl = _check_download(th, hash_dl, attempt_num=1)
    try_meta = _download_hash_metadata(th, check_hash_dl)
    assert hash_dl is None
    assert check_hash_dl is None
    assert try_meta is None


@pytest.mark.parametrize("hashes, attempt_num", [
    (hashes, 1),
    (hashes, 6)]
)
def test_retry_download(hashes, attempt_num):
    th = create_cbth_object(config_data._data['carbonblackcloud'])
    retry, attempt = _retry_download(th, hashes, attempt_num)
    assert attempt == attempt_num + 1
    if attempt_num > 5:
        assert retry == []
    else:
        assert len(retry.found) == 1
        assert len(retry.not_found) == 1
        assert len(retry.error) == 0

@pytest.mark.parametrize("hashes, attempt_num", [
    ([], 1)]
)
def test_retry_download_invalid(hashes, attempt_num):
    th = create_cbth_object(config_data._data['carbonblackcloud'])
    retry, attempt = _retry_download(th, hashes, attempt_num)
    assert retry is None
    assert attempt == attempt_num + 1


@pytest.mark.parametrize("hashes, attempt_num", [
    (hashes, 1),
    (hashes, 6)]
)
def test_check_download(hashes, attempt_num):
    th = create_cbth_object(config_data._data['carbonblackcloud'])
    hash_dl = _download_hashes(th, hashes)
    check_hash_dl = _check_download(th, hash_dl, attempt_num)
    assert len(check_hash_dl.found) == 1
    assert len(check_hash_dl.not_found) == 1
    assert len(check_hash_dl.error) == 0


@pytest.mark.parametrize("hashes, attempt_num", [
    (not_found_hashes, 1),
    (not_found_hashes, 6)]
)
def test_check_download_invalid(hashes, attempt_num):
    th = create_cbth_object(config_data._data['carbonblackcloud'])
    hash_dl = _download_hashes(th, hashes)
    check_hash_dl = _check_download(th, hash_dl, attempt_num)
    assert check_hash_dl is None


@pytest.mark.parametrize("hashes", [
    hashes]
)
def test_download(hashes):
    metadata = download(hashes)
    assert isinstance(metadata, list)
    assert isinstance(metadata[0], list)
    for item in metadata[0]:
        for key in metadata_valid.keys():
            assert key in item
