# -*- coding: utf-8 -*-

"""Test code for the persistence state manager."""


import pytest
from cbc_binary_toolkit.config import Config
from cbc_binary_toolkit.state.manager import BasePersistor, BasePersistorFactory, StateManager


class TestPersistor(BasePersistor):
    """Mockup of the persistor to be used in testing."""
    def set_checkpoint(self, binary_hash, engine_name, checkpoint_name, checkpoint_time=None):
        """
        Set a checkpoint on a binary hash/engine combination.

        Args:
            binary_hash (str): The hash value to set in the database.
            engine_name (str): The engine value to set in the database.
            checkpoint_name (str): The name of the checkpoint to set.
            checkpoint_time (str): The timestamp to set the checkpoint time to.  Not normally
            used except in test code.
        """
        assert engine_name == "default"
        if hasattr(self, "_sc"):
            self._sc = self._sc + 1
        else:
            self._sc = 1

    def get_previous_hashes(self, engine_name):
        """
        Returns a sorted list of all previously-completed hashes.

        Args:
            engine_name (str): The engine value to look up in the database.

        Returns:
            list: A list of all the hashes that have been marked as "done" for that engine. This list
            will be in sorted order.
        """
        assert engine_name == "default"
        if hasattr(self, "_gph"):
            self._gph = self._gph + 1
        else:
            self._gph = 1
        return ["a", "b", "c", "d", "e", "f"]

    def get_unfinished_hashes(self, engine_name):
        """
        Returns a sorted list of all not-completed hashes.

        Args:
            engine_name (str): The engine value to look up in the database.

        Returns:
            list: A list of all the hashes that are in the database but have not been marked as "done"
            for that engine.  This list is in the form of tuples, the first element of which is the hash,
            the second element of which is the last known checkpoint.
        """
        assert engine_name == "default"
        if hasattr(self, "_guh"):
            self._guh = self._guh + 1
        else:
            self._guh = 1
        return [("a", "METADATA"), ("b", "ANALYSIS")]

    def prune(self, timestamp):
        """
        Erases all entries from the database older than a specified time.

        Args:
            timestamp (str): The basic timestamp (ISO 8601 format). Everything older than this will be erased.
        """
        assert timestamp == "2020-01-01T00:00:00"
        if hasattr(self, "_p"):
            self._p = self._p + 1
        else:
            self._p = 1

    def add_report_item(self, severity, engine_name, data):
        """
        Adds a new report item (IOC record) to the current stored list.

        Args:
            severity (int): The severity level (1-10).
            engine_name (str): The engine value to store this data for.
            data (dict): The data item to be stored.
        """
        assert severity == 6
        assert engine_name == 'default'
        assert data['file_name'] == 'blort.exe'
        if hasattr(self, "_ari"):
            self._ari = self._ari + 1
        else:
            self._ari = 1

    def get_current_report_items(self, severity, engine_name):
        """
        Returns all current report items (IOC records) in the given list.

        Args:
            severity (int): The severity level (1-10).
            engine_name (str): The engine value to return data for.

        Returns:
            list: A list of dicts, each of which represents a report item.
        """
        assert severity == 6
        assert engine_name == 'default'
        if hasattr(self, "_gcri"):
            self._gcri = self._gcri + 1
        else:
            self._gcri = 1
        return [{'file_name': 'blort.exe'}, {'file_name': 'foobar.exe'}]

    def clear_report_items(self, severity, engine_name):
        """
        Clears all report items (IOC records) from a given list.

        Args:
            severity (int): The severity level (1-10).
            engine_name (str): The engine value to clear data for.
        """
        assert severity == 6
        assert engine_name == 'default'
        if hasattr(self, "_cri"):
            self._cri = self._cri + 1
        else:
            self._cri = 1


class TestPersistorFactory(BasePersistorFactory):
    """Mockup of the persistor factory to be used in testing."""
    def create_persistor(self, config):
        """
        Creates a new persistor object.

        Args:
            config (Config): The configuration section for the persistence parameters.

        Returns:
            Persistor: The new persistor object.
        """
        assert config.string("is_test") == "True"
        return TestPersistor()


@pytest.fixture
def local_config():
    """Configuration for all the test cases in this module."""
    return Config.load("""
    id: cbc_binary_toolkit
    version: 0.0.1
    database:
      _provider: test_persistence_manager.TestPersistorFactory
      is_test: "True"
    """)


def test_set_checkpoint(local_config):
    """Test the set_checkpoint() API."""
    manager = StateManager(local_config)
    manager.set_checkpoint("148429-4", "default", "DONE")
    assert getattr(manager._persistor, "_sc", 0) == 1
    assert getattr(manager._persistor, "_gph", 0) == 0
    assert getattr(manager._persistor, "_guh", 0) == 0
    assert getattr(manager._persistor, "_p", 0) == 0
    assert getattr(manager._persistor, "_ari", 0) == 0
    assert getattr(manager._persistor, "_gcri", 0) == 0
    assert getattr(manager._persistor, "_cri", 0) == 0


def test_get_previous_hashes(local_config):
    """Test the get_previous_hashes() API."""
    manager = StateManager(local_config)
    return_list = manager.get_previous_hashes("default")
    assert len(return_list) == 6
    assert getattr(manager._persistor, "_sc", 0) == 0
    assert getattr(manager._persistor, "_gph", 0) == 1
    assert getattr(manager._persistor, "_guh", 0) == 0
    assert getattr(manager._persistor, "_p", 0) == 0
    assert getattr(manager._persistor, "_ari", 0) == 0
    assert getattr(manager._persistor, "_gcri", 0) == 0
    assert getattr(manager._persistor, "_cri", 0) == 0


def test_get_unfinished_hashes(local_config):
    """Test the get_unfinished_hashes() API."""
    manager = StateManager(local_config)
    return_list = manager.get_unfinished_hashes("default")
    assert len(return_list) == 2
    assert getattr(manager._persistor, "_sc", 0) == 0
    assert getattr(manager._persistor, "_gph", 0) == 0
    assert getattr(manager._persistor, "_guh", 0) == 1
    assert getattr(manager._persistor, "_p", 0) == 0
    assert getattr(manager._persistor, "_ari", 0) == 0
    assert getattr(manager._persistor, "_gcri", 0) == 0
    assert getattr(manager._persistor, "_cri", 0) == 0


def test_prune(local_config):
    """Test the prune() API."""
    manager = StateManager(local_config)
    manager.prune("2020-01-01T00:00:00")
    assert getattr(manager._persistor, "_sc", 0) == 0
    assert getattr(manager._persistor, "_gph", 0) == 0
    assert getattr(manager._persistor, "_guh", 0) == 0
    assert getattr(manager._persistor, "_p", 0) == 1
    assert getattr(manager._persistor, "_ari", 0) == 0
    assert getattr(manager._persistor, "_gcri", 0) == 0
    assert getattr(manager._persistor, "_cri", 0) == 0


def test_add_report_item(local_config):
    """Test the add_report_item() API."""
    manager = StateManager(local_config)
    manager.add_report_item(6, 'default', {'file_name': 'blort.exe'})
    assert getattr(manager._persistor, "_sc", 0) == 0
    assert getattr(manager._persistor, "_gph", 0) == 0
    assert getattr(manager._persistor, "_guh", 0) == 0
    assert getattr(manager._persistor, "_p", 0) == 0
    assert getattr(manager._persistor, "_ari", 0) == 1
    assert getattr(manager._persistor, "_gcri", 0) == 0
    assert getattr(manager._persistor, "_cri", 0) == 0


def test_get_current_report_items(local_config):
    """Test the get_current_report_items() API."""
    manager = StateManager(local_config)
    items = manager.get_current_report_items(6, 'default')
    assert len(items) == 2
    assert getattr(manager._persistor, "_sc", 0) == 0
    assert getattr(manager._persistor, "_gph", 0) == 0
    assert getattr(manager._persistor, "_guh", 0) == 0
    assert getattr(manager._persistor, "_p", 0) == 0
    assert getattr(manager._persistor, "_ari", 0) == 0
    assert getattr(manager._persistor, "_gcri", 0) == 1
    assert getattr(manager._persistor, "_cri", 0) == 0


def test_clear_report_items(local_config):
    """Test the clear_report_items() API."""
    manager = StateManager(local_config)
    manager.clear_report_items(6, 'default')
    assert getattr(manager._persistor, "_sc", 0) == 0
    assert getattr(manager._persistor, "_gph", 0) == 0
    assert getattr(manager._persistor, "_guh", 0) == 0
    assert getattr(manager._persistor, "_p", 0) == 0
    assert getattr(manager._persistor, "_ari", 0) == 0
    assert getattr(manager._persistor, "_gcri", 0) == 0
    assert getattr(manager._persistor, "_cri", 0) == 1


def test_config_with_bogus_class():
    """Test the configuration while trying to load a bogus class."""
    cfg = Config.load("""
    id: cbc_binary_toolkit
    version: 0.0.1
    database:
      _provider: not_exist_package.NotExist
      is_test: "True"
    """)
    with pytest.raises(ImportError):
        StateManager(cfg)


def test_config_without_provider_set():
    """Test the configuration without having a provider class set."""
    cfg = Config.load("""
    id: cbc_binary_toolkit
    version: 0.0.1
    database:
      is_test: "True"
    """)
    with pytest.raises(KeyError):
        StateManager(cfg)
