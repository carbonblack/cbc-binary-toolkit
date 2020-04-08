# -*- coding: utf-8 -*-

"""Unit tests for the analysis engine"""

import pytest

from cbc_binary_toolkit import InitializationError
from cbc_binary_toolkit.config import Config
from cbc_binary_toolkit.engine import LocalEngineManager
from cbc_binary_toolkit.schemas import EngineResponseSchema

from tests.component.engine_fixtures.mock_engine import MockLocalEngine

ENGINE_NAME = "MockEngine"


@pytest.fixture(scope="session")
def config():
    """Configuration for all the test cases in this module."""
    return Config.load(f"""
    id: cbc_binary_toolkit
    version: 0.0.1
    engine:
      name: {ENGINE_NAME}
      local: True
      _provider: tests.component.engine_fixtures.mock_engine.MockLocalEngineFactory
      Test: TestPassed
    """)


# ==================================== TESTS BELOW ====================================

def test_create_engine(config):
    """Test successful creation of MockLocalEngine"""
    manager = LocalEngineManager(config)

    assert isinstance(manager.create_engine(), MockLocalEngine)


def test_analyze(config):
    """Test analyze pass through"""
    manager = LocalEngineManager(config)

    assert EngineResponseSchema.validate(manager.analyze({"sha256": "TEST_HASH"}))


@pytest.mark.parametrize("engine_config, exception", [
    ["""
        id: cbc_binary_toolkit
        engine:
          name: {ENGINE_NAME}
          local: False
          num_threads: 1
          _provider: tests.component.engine_fixtures.mock_engine.MockLocalEngineFactory
    """, InitializationError],
    ["""
        id: cbc_binary_toolkit
        engine:
          name: {ENGINE_NAME}
          local: True
          _provider: INVALID.INVALID
    """, ImportError],
    ["""
        id: cbc_binary_toolkit
        engine:
          name: {ENGINE_NAME}
          local: True
          _provider: cbc_binary_toolkit.engine.LocalEngineFactory
    """, NotImplementedError],
    [f"""
    id: cbc_binary_toolkit
    version: 0.0.1
    engine:
      name: {ENGINE_NAME}
      local: True
      _provider: tests.unit.engine_fixtures.mock_engine.MockLocalEngineFactory
    """, AssertionError]
])
def test_failed_init(engine_config, exception):
    """Test raised exceptions on init of LocalEngineManager"""
    config = Config.load(engine_config)
    with pytest.raises(exception):
        LocalEngineManager(config)
