# -*- coding: utf-8 -*-

"""Test code for the persistence state manager."""


import pytest
from cb_binary_analysis.config.model import Config
from cb_binary_analysis.state.manager import BasePersistor, BasePersistorFactory, StateManager


class TestPersistor(BasePersistor):
    """TODO"""
    def get_file_state(self, binary_hash, engine=None):
        """TODO"""
        if hasattr(self, "_gfs"):
            self._gfs = self._gfs + 1
        else:
            self._gfs = 1
        return {"file_hash": binary_hash, "file_name": "blort.exe"}

    def set_file_state(self, binary_hash, attrs, rowid=None):
        """TODO"""
        if rowid:
            assert rowid == 6681
        if hasattr(self, "_sfs"):
            self._sfs = self._sfs + 1
        else:
            self._sfs = 1
        return 6681

    def prune(self, timestamp):
        """TODO"""
        assert timestamp == "2020-01-01T00:00:00"
        if hasattr(self, "_p"):
            self._p = self._p + 1
        else:
            self._p = 1


class TestPersistorFactory(BasePersistorFactory):
    """TODO"""
    def create_persistor(self, config):
        """TODO"""
        assert config.string("is_test") == "True"
        return TestPersistor()


@pytest.fixture
def local_config():
    """Configuration for all the test cases in this module."""
    return Config.load("""
    id: cb-binary-analysis
    version: 0.0.1
    database:
      _provider: test_persistence_manager.TestPersistorFactory
      is_test: "True"
    """)


def test_lookup(local_config):
    """TODO"""
    manager = StateManager(local_config)
    attrs = manager.lookup("148429-4")
    assert attrs["file_hash"] == "148429-4"
    assert attrs["file_name"] == "blort.exe"
    assert getattr(manager._persistor, "_gfs", 0) == 1
    assert getattr(manager._persistor, "_sfs", 0) == 0
    assert getattr(manager._persistor, "_p", 0) == 0


def test_set_file_state(local_config):
    """TODO"""
    manager = StateManager(local_config)
    cookie = manager.set_file_state("148429-4", {})
    cookie2 = manager.set_file_state("148429-4", {}, cookie)
    assert cookie == cookie2
    assert getattr(manager._persistor, "_gfs", 0) == 0
    assert getattr(manager._persistor, "_sfs", 0) == 2
    assert getattr(manager._persistor, "_p", 0) == 0


def test_prune(local_config):
    """TODO"""
    manager = StateManager(local_config)
    manager.prune("2020-01-01T00:00:00")
    assert getattr(manager._persistor, "_gfs", 0) == 0
    assert getattr(manager._persistor, "_sfs", 0) == 0
    assert getattr(manager._persistor, "_p", 0) == 1


def test_config_with_bogus_class():
    """TODO"""
    cfg = Config.load("""
    id: cb-binary-analysis
    version: 0.0.1
    database:
      _provider: not_exist_package.NotExist
      is_test: "True"
    """)
    with pytest.raises(ImportError):
        StateManager(cfg)


def test_config_without_provider_set():
    """TODO"""
    cfg = Config.load("""
    id: cb-binary-analysis
    version: 0.0.1
    database:
      is_test: "True"
    """)
    with pytest.raises(KeyError):
        StateManager(cfg)
