# -*- coding: utf-8 -*-

"""Test code for the built-in PubSub manager."""


import pytest
from cbc_binary_toolkit.config import Config
from cbc_binary_toolkit.pubsub.manager import PubSubManager


@pytest.fixture
def local_config():
    """Configuration for all the test cases in this module."""
    return Config.load("""
    id: cbc_binary_toolkit
    version: 0.0.1
    pubsub:
      _provider: cbc_binary_toolkit.pubsub.builtin.Provider
    """)


def test_operate_on_one_queue(local_config):
    """Test to make sure we can put a payload into a queue and get it out."""
    manager = PubSubManager(local_config)
    testq = manager.create_queue('testq')

    payload = {'test_data': 'Ramthonodox'}
    testq.put(payload)
    output = testq.get()
    assert output == payload


def test_two_refs_to_same_queue(local_config):
    """Test that two references to the same queue result in proper operation."""
    manager = PubSubManager(local_config)
    testq_out = manager.create_queue('testq1')
    testq_in = manager.create_queue('testq1')

    payload = {'test_data': 'Ramthonodox'}
    testq_out.put(payload)
    output = testq_in.get()
    assert output == payload


def test_sequential_order(local_config):
    """Test that we get queued items out in the same order in which they went in."""
    manager = PubSubManager(local_config)
    testq = manager.create_queue('testq2')

    testq.put({'sequence': 1})
    testq.put({'sequence': 4})
    testq.put({'sequence': 9})

    output = testq.get()
    assert output['sequence'] == 1
    output = testq.get()
    assert output['sequence'] == 4
    output = testq.get()
    assert output['sequence'] == 9
