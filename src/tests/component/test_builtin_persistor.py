# -*- coding: utf-8 -*-

# *******************************************************
# Copyright (c) VMware, Inc. 2020. All Rights Reserved.
# SPDX-License-Identifier: MIT
# *******************************************************
# *
# * DISCLAIMER. THIS PROGRAM IS PROVIDED TO YOU "AS IS" WITHOUT
# * WARRANTIES OR CONDITIONS OF ANY KIND, WHETHER ORAL OR WRITTEN,
# * EXPRESS OR IMPLIED. THE AUTHOR SPECIFICALLY DISCLAIMS ANY IMPLIED
# * WARRANTIES OR CONDITIONS OF MERCHANTABILITY, SATISFACTORY QUALITY,
# * NON-INFRINGEMENT AND FITNESS FOR A PARTICULAR PURPOSE.

"""Test code for the built-in SQLite-based persistor."""


import pytest
import os

from sqlite3 import Cursor, OperationalError
from cbc_binary_toolkit.config import Config
from cbc_binary_toolkit.state.manager import StateManager


PERSISTENCE_FILE = "persist_test.db"


@pytest.fixture
def local_config():
    """Configuration for most of the test cases in this module."""
    return Config.load("""
    id: cbc_binary_toolkit
    version: 0.0.1
    database:
      _provider: cbc_binary_toolkit.state.builtin.Persistor
      location: ":memory:"
    """)


@pytest.fixture
def local_persistent_config():
    """Configuration for the persistence test cases in this module."""
    return Config.load(f"""
    id: cbc_binary_toolkit
    version: 0.0.1
    database:
      _provider: cbc_binary_toolkit.state.builtin.Persistor
      location: {PERSISTENCE_FILE}
    """)


class BreakingCursor(Cursor):
    """Mock for testing error handling"""
    def execute(self, statement, parameters=None):
        """Trigger exception"""
        raise OperationalError('in testing')


def _unfinished_as_map(l):
    """
    Utility to turn the "unfinished hashes" list into a map.

    Args:
        l (list): The list returned from get_unfinished_hashes().

    Returns:
        dict: The same hash expressed as a map.

    """
    return_value = {}
    for val in l:
        return_value[val[0]] = val[1]
    return return_value


def test_add_unfinished_hashes(local_config):
    """Tests adding hashes that are unfinished and getting them with get_unfinished_hashes()."""
    manager = StateManager(local_config)
    manager.set_checkpoint('ABCDEFGH', 'default', 'ALPHA')
    manager.set_checkpoint('EFGHIJKL', 'default', 'BRAVO')
    manager.set_checkpoint('ABCDEFGH', 'another', 'CHARLIE')
    return_list = manager.get_unfinished_hashes('default')
    assert len(return_list) == 2
    tmp = _unfinished_as_map(return_list)
    assert tmp['ABCDEFGH'] == 'ALPHA'
    assert tmp['EFGHIJKL'] == 'BRAVO'
    return_list = manager.get_unfinished_hashes('another')
    assert len(return_list) == 1
    tmp = _unfinished_as_map(return_list)
    assert tmp['ABCDEFGH'] == 'CHARLIE'


def test_add_finished_hashes(local_config):
    """Tests adding hashes that are finished and getting them with get_previous_hashes()."""
    manager = StateManager(local_config)
    manager.set_checkpoint('DEFGHIJK', 'default', 'DONE')
    manager.set_checkpoint('ABCDEFGH', 'default', 'DONE')
    manager.set_checkpoint('MNOPQRST', 'default', 'DONE')
    manager.set_checkpoint('ABCDEFGH', 'another', 'DONE')
    return_list = manager.get_previous_hashes('default')
    assert return_list == ['ABCDEFGH', 'DEFGHIJK', 'MNOPQRST']
    return_list = manager.get_previous_hashes('another')
    assert return_list == ['ABCDEFGH']


def test_add_mixed_hashes(local_config):
    """Tests adding both done and not-done hashes to make sure they're separated properly."""
    manager = StateManager(local_config)
    manager.set_checkpoint('ABCDEFGH', 'default', 'ALPHA')
    manager.set_checkpoint('DEFGHIJK', 'default', 'DONE')
    return_list = manager.get_unfinished_hashes('default')
    assert return_list == [('ABCDEFGH', 'ALPHA')]
    return_list = manager.get_previous_hashes('default')
    assert return_list == ['DEFGHIJK']


def test_update_existing_hash(local_config):
    """Tests updating an exising hash in the database, and how it affects the retrieval APIs."""
    manager = StateManager(local_config)
    manager.set_checkpoint('ABCDEFGH', 'default', 'ALPHA')
    return_list = manager.get_unfinished_hashes('default')
    assert return_list == [('ABCDEFGH', 'ALPHA')]
    return_list = manager.get_previous_hashes('default')
    assert return_list == []
    manager.set_checkpoint('ABCDEFGH', 'default', 'DONE')
    return_list = manager.get_unfinished_hashes('default')
    assert return_list == []
    return_list = manager.get_previous_hashes('default')
    assert return_list == ['ABCDEFGH']


def test_empty_database_retrieval(local_config):
    """Tests the two retrieval APIs on an empty database."""
    manager = StateManager(local_config)
    return_list = manager.get_unfinished_hashes('default')
    assert return_list == []
    return_list = manager.get_previous_hashes('default')
    assert return_list == []


def test_prune(local_config):
    """Tests the prune() functionality."""
    manager = StateManager(local_config)
    manager.set_checkpoint('DEFGHIJK', 'default', 'DONE', '2020-01-15T12:00:00')
    manager.set_checkpoint('ABCDEFGH', 'default', 'DONE', '2020-01-10T12:00:00')
    manager.set_checkpoint('MNOPQRST', 'default', 'DONE', '2020-01-15T12:00:00')
    manager.set_checkpoint('JKLMNOPQ', 'default', 'DONE', '2020-01-10T14:00:00')
    manager.prune("2020-01-12T00:00:00")
    return_list = manager.get_previous_hashes('default')
    assert return_list == ['DEFGHIJK', 'MNOPQRST']


def _test_check_report_items(reportlist, key, values):
    """Helper function for test_report_items."""
    checkoff = {}
    for v in values:
        checkoff[v] = True
    for element in reportlist:
        v = element.get(key, None)
        assert v is not None
        assert checkoff.get(v, False) is True
        del checkoff[v]
    assert checkoff == {}


def test_report_items(local_config):
    """Tests the management of report items."""
    manager = StateManager(local_config)
    manager.add_report_item(6, 'default', {'keyval': 1})
    manager.add_report_item(6, 'default', {'keyval': 4})
    manager.add_report_item(6, 'default', {'keyval': 9})
    manager.add_report_item(2, 'default', {'keyval': 2})
    manager.add_report_item(2, 'default', {'keyval': 3})
    _test_check_report_items(manager.get_current_report_items(6, 'default'), 'keyval', [1, 4, 9])
    _test_check_report_items(manager.get_current_report_items(2, 'default'), 'keyval', [2, 3])
    _test_check_report_items(manager.get_current_report_items(9, 'default'), 'keyval', [])
    manager.clear_report_items(6, 'default')
    _test_check_report_items(manager.get_current_report_items(6, 'default'), 'keyval', [])
    _test_check_report_items(manager.get_current_report_items(2, 'default'), 'keyval', [2, 3])
    _test_check_report_items(manager.get_current_report_items(9, 'default'), 'keyval', [])


def test_report_item_doubling(local_config):
    """Test that, when we add the same data to the report items twice, we get two copies."""
    manager = StateManager(local_config)
    manager.add_report_item(6, 'default', {'keyval': 42})
    manager.add_report_item(6, 'default', {'keyval': 42})
    returned_list = manager.get_current_report_items(6, 'default')
    assert returned_list == [{'keyval': 42}, {'keyval': 42}]


def test_report_items_nodata(local_config):
    """Tests the extraction of report items when there are none in the database."""
    manager = StateManager(local_config)
    items = manager.get_current_report_items(6, 'default')
    assert len(items) == 0


def test_exception_handling(local_config):
    """Tests that OperationalError is handled by all methods without throwing an exception."""
    manager = StateManager(local_config)
    manager._persistor._cursor_factory = BreakingCursor
    manager.set_checkpoint('ABCDEFGH', 'default', 'ALPHA')
    assert manager.get_previous_hashes('default') == []
    manager.prune("2020-01-12T00:00:00")
    manager.add_report_item(6, 'default', {'keyval': 1})
    assert manager.get_current_report_items(6, 'default') == []
    manager.clear_report_items(6, 'default')


def test_set_checkpoint_persistent(local_persistent_config):
    """Tests that set_checkpoint actually adds stuff to the database file on disk."""
    if os.path.exists(PERSISTENCE_FILE):
        os.remove(PERSISTENCE_FILE)
    manager = StateManager(local_persistent_config)
    manager.set_checkpoint('ABCDEFGH', 'default', 'ALPHA')
    manager.set_checkpoint('EFGHIJKL', 'default', 'BRAVO')
    manager.set_checkpoint('ABCDEFGH', 'another', 'CHARLIE')
    manager.force_close()
    manager2 = StateManager(local_persistent_config)
    return_list = manager2.get_unfinished_hashes('default')
    assert len(return_list) == 2
    return_list = manager2.get_unfinished_hashes('another')
    assert len(return_list) == 1


def test_add_report_item_persistent(local_persistent_config):
    """Tests that add_report_item actually adds stuff to the database file on disk."""
    if os.path.exists(PERSISTENCE_FILE):
        os.remove(PERSISTENCE_FILE)
    manager = StateManager(local_persistent_config)
    manager.add_report_item(6, 'default', {'keyval': 1})
    manager.add_report_item(6, 'default', {'keyval': 4})
    manager.add_report_item(6, 'default', {'keyval': 9})
    manager.add_report_item(2, 'default', {'keyval': 2})
    manager.add_report_item(2, 'default', {'keyval': 3})
    manager.force_close()
    manager2 = StateManager(local_persistent_config)
    _test_check_report_items(manager2.get_current_report_items(6, 'default'), 'keyval', [1, 4, 9])
    _test_check_report_items(manager2.get_current_report_items(2, 'default'), 'keyval', [2, 3])
    _test_check_report_items(manager2.get_current_report_items(9, 'default'), 'keyval', [])
