# -*- coding: utf-8 -*-

"""Test code for the built-in SQLite-based persistor."""


import pytest
from cbc_binary_sdk.config import Config
from cbc_binary_sdk.state.manager import StateManager


@pytest.fixture
def local_config():
    """Configuration for all the test cases in this module."""
    return Config.load("""
    id: cb-binary-analysis
    version: 0.0.1
    database:
      _provider: cbc_binary_sdk.state.builtin.Persistor
      location: ":memory:"
    """)


def test_file_state_create_and_alter(local_config):
    """TODO"""
    manager = StateManager(local_config)
    cookie = manager.set_file_state("ABCDEFGH", {"file_size": 2000000, "file_name": "blort.exe",
                                                 "os_type": "WINDOWS", "engine_name": "default"})
    state1 = manager.lookup("ABCDEFGH")
    assert state1["persist_id"] == cookie
    assert state1["file_size"] == 2000000
    assert state1["file_name"] == "blort.exe"
    assert state1["file_hash"] == "ABCDEFGH"
    assert state1["os_type"] == "WINDOWS"
    assert state1["engine_name"] == "default"
    assert "time_sent" not in state1
    assert "time_returned" not in state1
    assert "time_published" not in state1
    cookie2 = manager.set_file_state("ABCDEFGH", {"time_sent": "2020-02-01T04:00:00",
                                                  "time_returned": "2020-02-01T04:05:00"}, cookie)
    assert cookie2 == cookie
    state2 = manager.lookup("ABCDEFGH")
    assert state2["persist_id"] == cookie
    assert state2["file_size"] == 2000000
    assert state2["file_name"] == "blort.exe"
    assert state2["file_hash"] == "ABCDEFGH"
    assert state2["os_type"] == "WINDOWS"
    assert state2["engine_name"] == "default"
    assert state2["time_sent"] == "2020-02-01T04:00:00"
    assert state2["time_returned"] == "2020-02-01T04:05:00"
    assert "time_published" not in state2


def test_file_state_newest_selected(local_config):
    """TODO"""
    manager = StateManager(local_config)
    cookie1 = manager.set_file_state("ABCDEFGH", {"file_size": 2000000, "file_name": "blort.exe",
                                                  "os_type": "WINDOWS", "engine_name": "default",
                                                  "time_sent": "2020-01-15T12:00:00",
                                                  "time_returned": "2020-01-15T12:05:00",
                                                  "time_published": "2020-01-15T12:05:01"})
    manager.set_file_state("ABCDEFGH", {"file_size": 2000000, "file_name": "blort.exe",
                                        "os_type": "WINDOWS", "engine_name": "another",
                                        "time_sent": "2020-01-14T12:00:00",
                                        "time_returned": "2020-01-14T12:05:00",
                                        "time_published": "2020-01-14T12:05:01"})
    state = manager.lookup("ABCDEFGH")
    assert state["persist_id"] == cookie1
    assert state["engine_name"] == "default"
    assert state["time_sent"] == "2020-01-15T12:00:00"
    assert state["time_returned"] == "2020-01-15T12:05:00"
    assert state["time_published"] == "2020-01-15T12:05:01"


def test_file_state_multi_engine(local_config):
    """TODO"""
    manager = StateManager(local_config)
    cookie1 = manager.set_file_state("ABCDEFGH", {"file_size": 2000000, "file_name": "blort.exe",
                                                  "os_type": "WINDOWS", "engine_name": "default",
                                                  "time_sent": "2020-01-15T12:00:00",
                                                  "time_returned": "2020-01-15T12:05:00",
                                                  "time_published": "2020-01-15T12:05:01"})
    cookie2 = manager.set_file_state("ABCDEFGH", {"file_size": 2000000, "file_name": "blort.exe",
                                                  "os_type": "WINDOWS", "engine_name": "another",
                                                  "time_sent": "2020-01-14T12:00:00",
                                                  "time_returned": "2020-01-14T12:05:00",
                                                  "time_published": "2020-01-14T12:05:01"})
    state = manager.lookup("ABCDEFGH", "default")
    assert state["persist_id"] == cookie1
    assert state["engine_name"] == "default"
    assert state["time_sent"] == "2020-01-15T12:00:00"
    assert state["time_returned"] == "2020-01-15T12:05:00"
    assert state["time_published"] == "2020-01-15T12:05:01"
    state = manager.lookup("ABCDEFGH", "another")
    assert state["persist_id"] == cookie2
    assert state["engine_name"] == "another"
    assert state["time_sent"] == "2020-01-14T12:00:00"
    assert state["time_returned"] == "2020-01-14T12:05:00"
    assert state["time_published"] == "2020-01-14T12:05:01"


def test_file_state_not_found(local_config):
    """TODO"""
    manager = StateManager(local_config)
    state = manager.lookup("QRSTUVWXYZ")
    assert state is None
    
    
def test_file_state_unfinished(local_config):
    manager = StateManager(local_config)
    manager.set_file_state("ABCDEFGH", {"file_size": 2000000, "file_name": "blort.exe",
                                        "os_type": "WINDOWS", "engine_name": "default",
                                        "time_sent": "2020-01-15T12:00:00",
                                        "time_returned": "2020-01-15T12:05:00",
                                        "time_published": "2020-01-15T12:05:01"})
    manager.set_file_state("MNOPQRST", {"file_size": 2000000, "file_name": "foobar.exe",
                                        "os_type": "WINDOWS", "engine_name": "default",
                                        "time_sent": "2020-01-14T12:00:00",
                                        "time_returned": "2020-01-14T12:05:00"})
    output = manager.get_unfinished_states()
    assert len(output) == 1
    state = output[0]
    assert state["file_name"] == "foobar.exe"
    assert state["file_hash"] == "MNOPQRST"
    assert state["engine_name"] == "default"
    assert state["time_sent"] == "2020-01-14T12:00:00"
    assert state["time_returned"] == "2020-01-14T12:05:00"
    assert state.get('time_published', None) is None
    
    
def test_file_state_unfinished_none(local_config):
    manager = StateManager(local_config)
    manager.set_file_state("ABCDEFGH", {"file_size": 2000000, "file_name": "blort.exe",
                                        "os_type": "WINDOWS", "engine_name": "default",
                                        "time_sent": "2020-01-15T12:00:00",
                                        "time_returned": "2020-01-15T12:05:00",
                                        "time_published": "2020-01-15T12:05:01"})
    manager.set_file_state("MNOPQRST", {"file_size": 2000000, "file_name": "foobar.exe",
                                        "os_type": "WINDOWS", "engine_name": "default",
                                        "time_sent": "2020-01-14T12:00:00",
                                        "time_returned": "2020-01-14T12:05:00",
                                        "time_published": "2020-01-14T12:05:01"})
    output = manager.get_unfinished_states()
    assert len(output) == 0
        

def test_file_state_prune(local_config):
    """TODO"""
    manager = StateManager(local_config)
    cookie1 = manager.set_file_state("ABCDEFGH", {"file_size": 2000000, "file_name": "blort.exe",
                                                  "os_type": "WINDOWS", "engine_name": "default",
                                                  "time_sent": "2020-01-15T12:00:00",
                                                  "time_returned": "2020-01-15T12:05:00",
                                                  "time_published": "2020-01-15T12:05:01"})
    manager.set_file_state("EFGHIJKM", {"file_size": 2000000, "file_name": "foobar.exe",
                                        "os_type": "WINDOWS", "engine_name": "default",
                                        "time_sent": "2020-01-10T12:00:00",
                                        "time_returned": "2020-01-10T12:05:00",
                                        "time_published": "2020-01-10T12:05:01"})
    manager.prune("2020-01-12T00:00:00")
    state = manager.lookup("EFGHIJKM")
    assert state is None
    state = manager.lookup("ABCDEFGH")
    assert state["persist_id"] == cookie1
    assert state["file_name"] == "blort.exe"
    
    
def _test_check_report_items(list, key, values):
    checkoff = {}
    for v in values:
        checkoff[v] = True
    for element in list:
        v = element.get(key, None)
        assert v is not None
        assert checkoff.get(v, False) is True
        del checkoff[v]
    assert checkoff == {}    


def test_report_items(local_config):
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
