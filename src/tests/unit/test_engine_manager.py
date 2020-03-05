# -*- coding: utf-8 -*-

"""Unit tests for the analysis engine"""

import pytest

from cbc_binary_toolkit import InitializationError
from cbc_binary_toolkit.config import Config
from cbc_binary_toolkit.engine import LocalEngineManager
from cbc_binary_toolkit.pubsub import PubSubManager

ENGINE_NAME = "MockEngine"


@pytest.fixture(scope="session")
def config():
    """Configuration for all the test cases in this module."""
    return Config.load(f"""
    id: cbc_binary_toolkit
    version: 0.0.1
    pubsub:
      _provider: cbc_binary_toolkit.pubsub.builtin.Provider
      result_queue_name: results
    engine:
      name: {ENGINE_NAME}
      local: True
      num_threads: 1
      _provider: tests.unit.engine_fixtures.mock_engine.TestLocalEngineFactory
    """)


@pytest.fixture(scope="function")
def pub_sub_manager(config):
    """Creates pub_sub for IngestionActor"""
    manager = PubSubManager(config)
    manager.create_queue(config.get("engine.name"))
    manager.create_queue(config.get("pubsub.result_queue_name"))
    return manager


# ==================================== TESTS BELOW ====================================

def test_execution(config, pub_sub_manager):
    """Test successful execution of LocalEngineManager"""
    manager = LocalEngineManager(config, pub_sub_manager)

    manager.start()
    pub_sub_manager.put(config.get("engine.name"), "TEST_DATA")
    manager.stop()
    assert pub_sub_manager.get(config.get("pubsub.result_queue_name")) == "TEST_DATA"


@pytest.mark.parametrize("engine_config, exception", [
    ["""
        id: cbc_binary_toolkit
        engine:
          name: {ENGINE_NAME}
          local: False
          num_threads: 1
          _provider: tests.unit.engine_fixtures.mock_engine.TestLocalEngineFactory
    """, InitializationError],
    ["""
        id: cbc_binary_toolkit
        engine:
          name: {ENGINE_NAME}
          local: True
          num_threads: 0
          _provider: tests.unit.engine_fixtures.mock_engine.TestLocalEngineFactory
    """, InitializationError],
    ["""
        id: cbc_binary_toolkit
        engine:
          name: {ENGINE_NAME}
          local: True
          num_threads: 1
          _provider: INVALID.INVALID
    """, ImportError],
    ["""
        id: cbc_binary_toolkit
        engine:
          name: {ENGINE_NAME}
          local: True
          num_threads: 1
          _provider: cbc_binary_toolkit.engine.LocalEngineFactory
    """, NotImplementedError]
])
def test_failed_init(engine_config, exception):
    """Test successful execution of LocalEngineManager"""
    config = Config.load(engine_config)
    with pytest.raises(exception):
        LocalEngineManager(config, pub_sub_manager)
