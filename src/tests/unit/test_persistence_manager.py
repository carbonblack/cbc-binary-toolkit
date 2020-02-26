# -*- coding: utf-8 -*-

"""Test code for the persistence state manager."""


import pytest
from cbc_binary_toolkit.config import Config
from cbc_binary_toolkit.state.manager import BasePersistor, BasePersistorFactory, StateManager


class TestPersistor(BasePersistor):
    """Mockup of the persistor to be used in testing."""
    def get_file_state(self, binary_hash, engine=None):
        """
        Get the stored file state for a specified hash value.

        :param binary_hash str: The hash value to look up in the database.
        :param engine str: (Optional) The engine value to look up in the database.
        :return: A dict containing the file information, or None if not found.
        """
        if hasattr(self, "_gfs"):
            self._gfs = self._gfs + 1
        else:
            self._gfs = 1
        return {"file_hash": binary_hash, "file_name": "blort.exe"}

    def set_file_state(self, binary_hash, attrs, rowid=None):
        """
        Set the stored file state for a specified hash value.

        :param binary_hash str: The hash value to set in the database.
        :param attrs dict: The attributes to set as part of the hash value entry.
        :param persist_id int: The persistence ID of the existing record we're modifying (optional).
        :return: The persistence ID of the database row, either new or existing.
        """
        if rowid:
            assert rowid == 6681
        if hasattr(self, "_sfs"):
            self._sfs = self._sfs + 1
        else:
            self._sfs = 1
        return 6681

    def get_unfinished_states(self, engine=None):
        """
        Returns all states not marked as "analysis finished" (possibly for a single engine).

        :param engine str: (Optional) The engine value to look up in the database.
        :return: A list of dicts containing all unfinished file information. Returns an empty list if none present.
        """
        if hasattr(self, "_gus"):
            self._gus = self._gus + 1
        else:
            self._gus = 1
        return [{"file_hash": "ABCDEFG", "file_name": "blort.exe"}]

    def get_num_unfinished_states(self):
        """
        Returns the number of unfinished states in the persistence manager for each known engine.

        :return: A dict with engine names as keys and count of results for each engine as values.
        """
        if hasattr(self, "_gnss"):
            self._gnss = self._gnss + 1
        else:
            self._gnss = 1
        return {"default": 2, "another": 1}

    def prune(self, timestamp):
        """
        Erases all entries from the database older than a specified time.

        :param timestamp str: The basic timestamp. Everything older than this will be erased.
        """
        assert timestamp == "2020-01-01T00:00:00"
        if hasattr(self, "_p"):
            self._p = self._p + 1
        else:
            self._p = 1

    def add_report_item(self, severity, engine, data):
        """
        Adds a new report item (IOC record) to the current stored list.

        :param severity int: The severity level (1-10).
        :param engine str: The engine value to store this data for.
        :param data dict: The data item to be stored.
        """
        assert severity == 6
        assert engine == 'default'
        assert data['file_name'] == 'blort.exe'
        if hasattr(self, "_ari"):
            self._ari = self._ari + 1
        else:
            self._ari = 1

    def get_current_report_items(self, severity, engine):
        """
        Returns all current report items (IOC records) in the given list.

        :param severity int: The severity level (1-10).
        :param engine str: The engine value to return data for.
        :return: A list of dicts, each of which represents a report item.
        """
        assert severity == 6
        assert engine == 'default'
        if hasattr(self, "_gcri"):
            self._gcri = self._gcri + 1
        else:
            self._gcri = 1
        return [{'file_name': 'blort.exe'}, {'file_name': 'foobar.exe'}]

    def clear_report_items(self, severity, engine):
        """
        Clears all report items (IOC records) from a given list.

        :param severity int: The severity level (1-10).
        :param engine str: The engine value to clear data for.
        """
        assert severity == 6
        assert engine == 'default'
        if hasattr(self, "_cri"):
            self._cri = self._cri + 1
        else:
            self._cri = 1


class TestPersistorFactory(BasePersistorFactory):
    """Mockup of the persistor factory to be used in testing."""
    def create_persistor(self, config):
        """
        Creates a new persistor object.

        :param config Config: The configuration section for the persistence parameters.
        :return: The new persistor object.
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


def test_lookup(local_config):
    """Test the lookup() API."""
    manager = StateManager(local_config)
    attrs = manager.lookup("148429-4")
    assert attrs["file_hash"] == "148429-4"
    assert attrs["file_name"] == "blort.exe"
    assert getattr(manager._persistor, "_gfs", 0) == 1
    assert getattr(manager._persistor, "_sfs", 0) == 0
    assert getattr(manager._persistor, "_gus", 0) == 0
    assert getattr(manager._persistor, "_gnss", 0) == 0
    assert getattr(manager._persistor, "_p", 0) == 0
    assert getattr(manager._persistor, "_ari", 0) == 0
    assert getattr(manager._persistor, "_gcri", 0) == 0
    assert getattr(manager._persistor, "_cri", 0) == 0


def test_set_file_state(local_config):
    """Test the set_file_state() API."""
    manager = StateManager(local_config)
    cookie = manager.set_file_state("148429-4", {})
    cookie2 = manager.set_file_state("148429-4", {}, cookie)
    assert cookie == cookie2
    assert getattr(manager._persistor, "_gfs", 0) == 0
    assert getattr(manager._persistor, "_sfs", 0) == 2
    assert getattr(manager._persistor, "_gus", 0) == 0
    assert getattr(manager._persistor, "_gnss", 0) == 0
    assert getattr(manager._persistor, "_p", 0) == 0
    assert getattr(manager._persistor, "_ari", 0) == 0
    assert getattr(manager._persistor, "_gcri", 0) == 0
    assert getattr(manager._persistor, "_cri", 0) == 0


def test_get_unfinished_states(local_config):
    """Test the get_unfinished_states() API."""
    manager = StateManager(local_config)
    states = manager.get_unfinished_states()
    assert len(states) == 1
    assert getattr(manager._persistor, "_gfs", 0) == 0
    assert getattr(manager._persistor, "_sfs", 0) == 0
    assert getattr(manager._persistor, "_gus", 0) == 1
    assert getattr(manager._persistor, "_gnss", 0) == 0
    assert getattr(manager._persistor, "_p", 0) == 0
    assert getattr(manager._persistor, "_ari", 0) == 0
    assert getattr(manager._persistor, "_gcri", 0) == 0
    assert getattr(manager._persistor, "_cri", 0) == 0


def test_get_num_unfinished_states(local_config):
    """Test the get_num_unfinished_states() API."""
    manager = StateManager(local_config)
    counts = manager.get_num_unfinished_states()
    assert counts['default'] == 2
    assert counts['another'] == 1
    assert getattr(manager._persistor, "_gfs", 0) == 0
    assert getattr(manager._persistor, "_sfs", 0) == 0
    assert getattr(manager._persistor, "_gus", 0) == 0
    assert getattr(manager._persistor, "_gnss", 0) == 1
    assert getattr(manager._persistor, "_p", 0) == 0
    assert getattr(manager._persistor, "_ari", 0) == 0
    assert getattr(manager._persistor, "_gcri", 0) == 0
    assert getattr(manager._persistor, "_cri", 0) == 0


def test_prune(local_config):
    """Test the prune() API."""
    manager = StateManager(local_config)
    manager.prune("2020-01-01T00:00:00")
    assert getattr(manager._persistor, "_gfs", 0) == 0
    assert getattr(manager._persistor, "_sfs", 0) == 0
    assert getattr(manager._persistor, "_gus", 0) == 0
    assert getattr(manager._persistor, "_gnss", 0) == 0
    assert getattr(manager._persistor, "_p", 0) == 1
    assert getattr(manager._persistor, "_ari", 0) == 0
    assert getattr(manager._persistor, "_gcri", 0) == 0
    assert getattr(manager._persistor, "_cri", 0) == 0


def test_add_report_item(local_config):
    """Test the add_report_item() API."""
    manager = StateManager(local_config)
    manager.add_report_item(6, 'default', {'file_name': 'blort.exe'})
    assert getattr(manager._persistor, "_gfs", 0) == 0
    assert getattr(manager._persistor, "_sfs", 0) == 0
    assert getattr(manager._persistor, "_gus", 0) == 0
    assert getattr(manager._persistor, "_gnss", 0) == 0
    assert getattr(manager._persistor, "_p", 0) == 0
    assert getattr(manager._persistor, "_ari", 0) == 1
    assert getattr(manager._persistor, "_gcri", 0) == 0
    assert getattr(manager._persistor, "_cri", 0) == 0


def test_get_current_report_items(local_config):
    """Test the get_current_report_items() API."""
    manager = StateManager(local_config)
    items = manager.get_current_report_items(6, 'default')
    assert len(items) == 2
    assert getattr(manager._persistor, "_gfs", 0) == 0
    assert getattr(manager._persistor, "_sfs", 0) == 0
    assert getattr(manager._persistor, "_gus", 0) == 0
    assert getattr(manager._persistor, "_gnss", 0) == 0
    assert getattr(manager._persistor, "_p", 0) == 0
    assert getattr(manager._persistor, "_ari", 0) == 0
    assert getattr(manager._persistor, "_gcri", 0) == 1
    assert getattr(manager._persistor, "_cri", 0) == 0


def test_clear_report_items(local_config):
    """Test the clear_report_items() API."""
    manager = StateManager(local_config)
    manager.clear_report_items(6, 'default')
    assert getattr(manager._persistor, "_gfs", 0) == 0
    assert getattr(manager._persistor, "_sfs", 0) == 0
    assert getattr(manager._persistor, "_gus", 0) == 0
    assert getattr(manager._persistor, "_gnss", 0) == 0
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
