# -*- coding: utf-8 -*-

"""Test code for the persistence state manager."""


import pytest
from cb_binary_analysis.config.model import Config
from cb_binary_analysis.state.manager import StateManager


class TestPersistor:
    def get_file_state(self, hashval):
        if hasattr(self, "_gfs"):
            self._gfs = self._gfs + 1
        else:
            self._gfs = 1
        return {"file_hash": hashval, "file_name": "blort.exe"}

    def set_file_state(self, hashval, attrs, rowid=None):
        if rowid:
            assert rowid == 6681
        if hasattr(self, "_sfs"):
            self._sfs = self._sfs + 1
        else:
            self._sfs = 1
        return 6681

    def prune(self, timestamp):
        assert timestamp == "2020-01-01T00:00:00"
        if hasattr(self, "_p"):
            self._p = self._p + 1
        else:
            self._p = 1


class TestPersistorFactory:
    def create_persistor(self, config):
        assert config.string("is_test") == "True"
        return TestPersistor()


@pytest.fixture
def local_config():
    """
    Configuration for all the test cases in this module.
    """
    return Config.load("""
    id: cb-binary-analysis
    version: 0.0.1
    database:
      _provider: test_persistence_manager.TestPersistorFactory
      is_test: "True"
    """)


def test_lookup(local_config):
    manager = StateManager(local_config)
    attrs = manager.lookup("148429-4")
    assert attrs["file_hash"] == "148429-4"
    assert attrs["file_name"] == "blort.exe"
    assert getattr(manager._persistor, "_gfs", 0) == 1
    assert getattr(manager._persistor, "_sfs", 0) == 0
    assert getattr(manager._persistor, "_p", 0) == 0


def test_set_file_state(local_config):
    manager = StateManager(local_config)
    cookie = manager.set_file_state("148429-4", {})
    cookie2 = manager.set_file_state("148429-4", {}, cookie)
    assert cookie == cookie2
    assert getattr(manager._persistor, "_gfs", 0) == 0
    assert getattr(manager._persistor, "_sfs", 0) == 2
    assert getattr(manager._persistor, "_p", 0) == 0


def test_prune(local_config):
    manager = StateManager(local_config)
    manager.prune("2020-01-01T00:00:00")
    assert getattr(manager._persistor, "_gfs", 0) == 0
    assert getattr(manager._persistor, "_sfs", 0) == 0
    assert getattr(manager._persistor, "_p", 0) == 1
