# -*- coding: utf-8 -*-

"""Test code for the built-in SQS PubSub manager (LocalStack)."""


import pytest
import os
from cb_binary_analysis.config.model import Config
from cb_binary_analysis.pubsub.manager import PubSubManager


@pytest.fixture
def local_config():
    """
    Configuration for all the test cases in this module.
    """
    server_loc = os.environ.get('SQS_TEST_SERVER_ADDR') or 'localhost'
    return Config.load("""
    id: cb-binary-analysis
    version: 0.0.1
    pubsub:
      _provider: cb_binary_analysis.pubsub.builtin.Provider
      region: us-east-1
      endpoint_URL: http://{}:4576
      access_key_id: ABCDEF
      access_key: 0123456789ABCDEF
    """.format(server_loc))


def test_operate_on_one_queue(local_config):
    manager = PubSubManager(local_config)
    testq = manager.create_queue('testq')

    payload = {'test_data': 'Ramthonodox'}
    testq.put(payload)
    output = testq.get()
    assert output == payload


def test_two_refs_to_same_queue(local_config):
    manager = PubSubManager(local_config)
    testq_out = manager.create_queue('testq1')
    testq_in = manager.create_queue('testq1')

    payload = {'test_data': 'Ramthonodox'}
    testq_out.put(payload)
    output = testq_in.get()
    assert output == payload


def test_sequential_order(local_config):
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
