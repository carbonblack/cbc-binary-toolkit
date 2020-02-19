# -*- coding: utf-8 -*-

"""Test code for the persistence state manager."""


import pytest
from cb_binary_analysis.config.model import Config
from cb_binary_analysis.pubsub.manager import BaseQueue, BaseProvider, BaseProviderFactory, PubSubManager


class TestQueue(BaseQueue):
    """TODO"""
    def put(self, workitem):
        """TODO"""
        assert workitem["foo"] == "bar"
        if hasattr(self, "_p"):
            self._p = self._p + 1
        else:
            self._p = 1

    def get(self):
        """TODO"""
        if hasattr(self, "_g"):
            self._g = self._g + 1
        else:
            self._g = 1
        return {"foo": "bar"}


class TestProvider(BaseProvider):
    """TODO"""
    def create_queue(self, queue_name):
        """TODO"""
        q = TestQueue()
        q._name = queue_name
        return q


class TestProviderFactory(BaseProviderFactory):
    """TODO"""
    def create_pubsub_provider(self, config):
        """TODO"""
        assert config.string("is_test") == "True"
        return TestProvider()


@pytest.fixture
def local_config():
    """Configuration for all the test cases in this module."""
    return Config.load("""
    id: cb-binary-analysis
    version: 0.0.1
    pubsub:
      _provider: test_pubsub_manager.TestProviderFactory
      is_test: "True"
    """)


def test_get(local_config):
    """TODO"""
    manager = PubSubManager(local_config)
    queue = manager.create_queue("blort")
    assert queue._name == "blort"
    result = queue.get()
    assert result["foo"] == "bar"
    assert getattr(queue, "_g", 0) == 1
    assert getattr(queue, "_p", 0) == 0


def test_put(local_config):
    """TODO"""
    manager = PubSubManager(local_config)
    queue = manager.create_queue("blort")
    assert queue._name == "blort"
    queue.put({"foo": "bar"})
    assert getattr(queue, "_g", 0) == 0
    assert getattr(queue, "_p", 0) == 1
