import pytest

class CBAPIMock:
    def __init__(self, monkeypatch, api):
        self.mocks = {}
        self.monkeypatch = monkeypatch
        self.api = api
        monkeypatch.setattr(api, "get_object", self._self_get_object())
        monkeypatch.setattr(api, "get_raw_data", self._self_get_raw_data())
        monkeypatch.setattr(api, "post_object", self._self_post_object())
        monkeypatch.setattr(api, "put_object", self._self_put_object())
        monkeypatch.setattr(api, "delete_object", self._self_delete_object())


    class StubResponse(object):
        def __init__(self, contents, scode=200):
            self._contents = contents
            self.status_code = scode

        def json(self):
            return self._contents

    def get_mock_key(self, verb, url):
        return "{}:{}".format(verb, url)

    def mock_request(self, verb, url, body):
        if verb is "GET" or verb is "RAW_GET":
            self.mocks["{}:{}".format(verb, url)] = body
        else:
            self.mocks["{}:{}".format(verb, url)] = self.StubResponse(body)

    """
        Factories for mocked API requests
    """
    def _self_get_object(self):
        def _get_object(url, params=None, default=None):
            if self.get_mock_key("GET", url) in self.mocks:
                return self.mocks[self.get_mock_key("GET", url)]
            pytest.fail("GET called for %s when it shouldn't be" % url)
        return _get_object

    def _self_post_object(self):
        def _post_object(url, body, **kwargs):
            if self.get_mock_key("POST", url) in self.mocks:
                return self.mocks[self.get_mock_key("POST", url)]
            pytest.fail("POST called for %s when it shouldn't be" % url)
        return _post_object

    def _self_get_raw_data(self):
        def _get_raw_data(url, query_params, **kwargs):
            if self.get_mock_key("RAW_GET", url) in self.mocks:
                return self.mocks[self.get_mock_key("RAW_GET", url)]
            pytest.fail("Raw GET called for %s when it shouldn't be" % url)
        return _get_raw_data

    def _self_put_object(self):
        def _put_object(url, body, **kwargs):
            if self.get_mock_key("PUT", url) in self.mocks:
                return self.mocks[self.get_mock_key("PUT", url)]
            pytest.fail("PUT called for %s when it shouldn't be" % url)
        return _put_object

    def _self_delete_object(self):
        def _delete_object(url):
            if self.get_mock_key("DELETE", url) in self.mocks:
                return self.mocks[self.get_mock_key("DELETE", url)]
            pytest.fail("DELETE called for %s when it shouldn't be" % url)
        return _delete_object
