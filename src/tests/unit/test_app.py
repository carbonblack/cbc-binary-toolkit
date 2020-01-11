import fakeredis
from utils.queues import EngineQueue
from utils.CBAPIMock import CBAPIMock
from werkzeug import exceptions
import app
import pytest
import json

import os
os.environ['UNIT_TEST'] = 'true'


@pytest.fixture(scope="function")
def mock_redis(monkeypatch):
    redis = fakeredis.FakeStrictRedis()
    monkeypatch.setattr(app, "database", redis)
    app.app.config["engine_queues"]["test"] = EngineQueue("test", redis)
    return redis


@pytest.fixture(scope="function")
def cbapi_mock(monkeypatch):
    return CBAPIMock(monkeypatch, app.cbth)


def test_process_hashes_bad_request():
    with pytest.raises(exceptions.BadRequest):
        assert app.process_hashes('string')


def test_process_hashes_success(monkeypatch, cbapi_mock, mock_redis):

    cbapi_mock.mock_request("GET", "/ubs/v1/orgs/WNEXFKQ7/sha256/1d35014d937e02ee090a0cfc903ee6e6b1b65c832694519f2b4dc4c74d3eb0fd/metadata",
                            {
                                "sha256": "1d35014d937e02ee090a0cfc903ee6e6b1b65c832694519f2b4dc4c74d3eb0fd",
                                "architecture": [
                                    "amd64"
                                ],
                                "available_file_size": 30208,
                                "charset_id": 1200,
                                "comments": None,
                                "company_name": "Microsoft Corporation",
                                "copyright": "© Microsoft Corporation. All rights reserved.",
                                "file_available": True,
                                "file_description": "Host Process for Windows Services",
                                "file_size": 30208,
                                "file_version": "6.2.9200.16384 (win8_rtm.120725-1247)",
                                "internal_name": "svchost.exe",
                                "lang_id": 1033,
                                "md5": "57350bede3834915b6145b67c71c7bda",
                                "original_filename": "svchost.exe",
                                "os_type": "WINDOWS",
                                "private_build": None,
                                "product_description": None,
                                "product_name": "Microsoft® Windows® Operating System",
                                "product_version": "6.2.9200.16384",
                                "special_build": None,
                                "trademark": None
                            })
    cbapi_mock.mock_request("POST", "/ubs/v1/orgs/WNEXFKQ7/file/_download",
                            {
                                "found": [
                                    {
                                        "sha256": "1d35014d937e02ee090a0cfc903ee6e6b1b65c832694519f2b4dc4c74d3eb0fd",
                                        "url": "https://s3-bucket.test"
                                    }
                                ],
                                "not_found": [],
                                "error": []
                            })

    app.process_hashes(['1d35014d937e02ee090a0cfc903ee6e6b1b65c832694519f2b4dc4c74d3eb0fd'])

    entry = mock_redis.blpop(['test'])
    if entry is None:
        pytest.fail("Binary meta data not pushed to queue")

    binary_meta_data = json.loads(entry[1].decode())
    assert(binary_meta_data['sha256'] == "1d35014d937e02ee090a0cfc903ee6e6b1b65c832694519f2b4dc4c74d3eb0fd")
