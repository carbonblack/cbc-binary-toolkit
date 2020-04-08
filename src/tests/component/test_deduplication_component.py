# -*- coding: utf-8 -*-

"""Unit tests for the deduplication component"""

import pytest
from cbc_binary_toolkit.config import Config
from cbc_binary_toolkit.state.manager import BasePersistor
from cbc_binary_toolkit.deduplication_component import DeduplicationComponent


class StubPersistor(BasePersistor):
    """Used to supply the result of get_previous_hashes to the deduplication component."""
    def __init__(self, prev_hash_response):
        """Constructor"""
        self._prev_hash_response = prev_hash_response

    def get_previous_hashes(self, engine_name):
        """Stub get_previous_hashes"""
        assert engine_name == "default"
        return self._prev_hash_response


@pytest.fixture
def local_config():
    """Configuration for all the test cases in this module."""
    return Config.load("""
    id: cbc_binary_toolkit
    version: 0.0.1
    engine:
        name: "default"
    """)


def equivalent(list1, list2):
    """Ensures that two lists are equivalent, i.e., contain the same items."""
    if len(list1) != len(list2):
        return False
    set1 = set(list1)
    for item in list2:
        if item not in set1:
            return False
    return True


@pytest.mark.parametrize(["input_list", "previous_list", "result_list"], [
    (["ABCD", "DEFG", "JKLM"], ["ABCD", "CDEF"], ["DEFG", "JKLM"]),
    (["ABCD", "DEFG", "JKLM"], ["ABCD", "DEFG"], ["JKLM"]),
    (["ABCD", "DEFG", "JKLM"], ["CDEF", "GHIJ"], ["ABCD", "DEFG", "JKLM"]),
    (["ABCD", "DEFG", "JKLM"], ["ABCD", "DEFG", "JKLM"], []),
    (["ABCD", "DEFG", "JKLM"], [], ["ABCD", "DEFG", "JKLM"]),
    ([], ["ABCD", "CDEF"], []),
    ([], [], [])
])
def test_deduplication(local_config, input_list, previous_list, result_list):
    """Test various combinations of deduplication inputs and outputs."""
    state_manager = StubPersistor(previous_list)
    sut = DeduplicationComponent(local_config, state_manager)
    return_list = sut.deduplicate(input_list)
    assert equivalent(return_list, result_list), f"{return_list} != {result_list}"