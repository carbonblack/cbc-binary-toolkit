# -*- coding: utf-8 -*-

"""Test code for the persistence state manager."""


import pytest
from cbc_binary_sdk.config import Config
from cbc_binary_sdk.pubsub.manager import BaseQueue, BaseProvider, BaseProviderFactory, PubSubManager


class TestQueue(BaseQueue):
    """Mockup of a queue object."""
    def put(self, workitem):
        """
        Puts a new work item on the queue.

        :param workitem dict: The work item to put on the queue.
        """
        assert workitem["foo"] == "bar"
        if hasattr(self, "_p"):
            self._p = self._p + 1
        else:
            self._p = 1

    def get(self):
        """
        Retrieves a new work item from the queue.

        If there are no work items available, blocks until one becomes available.

        :return: The first work item on the queue.
        """
        if hasattr(self, "_g"):
            self._g = self._g + 1
        else:
            self._g = 1
        return {"foo": "bar"}


class TestProvider(BaseProvider):
    """Mockup of the PubSub provider."""
    def create_queue(self, queue_name):
        """
        Creates a new PubSub queue.  If one already exists by that name, returns that instance.

        :param queue_name str: The name for the new queue.
        :return: The new queue object.
        """
        q = TestQueue()
        q._name = queue_name
        return q

    def get_queue(self, queue_name):
        """
        Gets a PubSub queue by name.

        :param queue_name str: The name for the new queue.
        :return: The new queue object.
        """
        return None


class TestProviderFactory(BaseProviderFactory):
    """Mockup of the PubSub provider factory."""
    def create_pubsub_provider(self, config):
        """
        Creates a new PubSub provider object.

        :param config Config: The configuration section for the persistence parameters.
        :return: The new provider factory object.
        """
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
    """Test the get() API."""
    manager = PubSubManager(local_config)
    queue = manager.create_queue("blort")
    assert queue._name == "blort"
    result = queue.get()
    assert result["foo"] == "bar"
    assert getattr(queue, "_g", 0) == 1
    assert getattr(queue, "_p", 0) == 0


def test_put(local_config):
    """Test the put() API."""
    manager = PubSubManager(local_config)
    queue = manager.create_queue("blort")
    assert queue._name == "blort"
    queue.put({"foo": "bar"})
    assert getattr(queue, "_g", 0) == 0
    assert getattr(queue, "_p", 0) == 1


def test_queue_ops(local_config):
    """Test the operations of the PubSub provider."""
    manager = PubSubManager(local_config)
    queue = manager.create_queue('blort')
    assert queue._name == "blort"
    queue = manager.get_queue('foobar')
    assert queue is None
