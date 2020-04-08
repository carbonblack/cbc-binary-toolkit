# -*- coding: utf-8 -*-

"""Unit tests for input functions"""

import pytest
import os

from cbc_binary_toolkit.cli_input import read_csv, read_json
from typing import List, Dict
from json import JSONDecodeError

from tests.component.input_fixtures.file_path_constants import (
    BASIC_INPUT_FILE,
    LARGE_INPUT_FILE,
    BASIC_JSON_INPUT_FILE,
    LARGE_JSON_INPUT_FILE,
    BASIC_INPUT_ANSWER_PATH,
    LARGE_INPUT_ANSWER_PATH,
    BASIC_JSON_ANSWER_PATH,
    LARGE_JSON_ANSWER_PATH,
    BASIC_JSON_WRONG_HASHLEN,
    BASIC_JSON_MALFORMED_FILE,
    BASIC_INPUT_CSV_WRONG_HASHLEN,
    DOES_NOT_EXIST_FILE,
    EMPTY_CSV,
    # WRONG_KEY_JSON,
    EMPTY_HASHES_DICT_JSON
)


def attach_path(path):
    """Attaches local file path to location"""
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), path)


class TestInputFunctions():
    """Unit tests for input.py functions"""
    @pytest.mark.parametrize("input_file_path, answer_file_path", [
        (BASIC_INPUT_FILE, BASIC_INPUT_ANSWER_PATH),
        (LARGE_INPUT_FILE, LARGE_INPUT_ANSWER_PATH)
    ])
    def test_csv(self, input_file_path: str, answer_file_path: List[Dict]):
        """Unit testing read_csv function"""
        with open(attach_path(answer_file_path), 'r') as answer_file:
            csv_file = open(attach_path(input_file_path))
            assert str(read_csv(csv_file)) == answer_file.read().strip()

    @pytest.mark.parametrize("input_file_path, answer_file_path", [
        (BASIC_JSON_INPUT_FILE, BASIC_JSON_ANSWER_PATH),
        (LARGE_JSON_INPUT_FILE, LARGE_JSON_ANSWER_PATH)
    ])
    def test_json(self, input_file_path: str, answer_file_path: List[Dict]):
        """Unit testing read_json function"""
        with open(attach_path(input_file_path), 'r') as input_file:
            with open(attach_path(answer_file_path), 'r') as answer_file:
                assert str(read_json(input_file.read().strip())) == answer_file.read().strip()

    @pytest.mark.parametrize("error, input_file_path, msg", [
        (
            AssertionError,
            BASIC_INPUT_CSV_WRONG_HASHLEN,
            "Hash should be 64 chars, instead is 63 chars: "
            "qqtrqoetfdomjjqnyatgmmbomhtnzqchzqzhxggmxqzgoabcnzysikrmunjgrup"),
        (OSError, DOES_NOT_EXIST_FILE, f"[Errno 2] No such file or directory: '{attach_path(DOES_NOT_EXIST_FILE)}'"),
        (AssertionError, EMPTY_CSV, f'There are no hashes in File {attach_path(EMPTY_CSV)}')
    ])
    def test_csv_exceptions(self, error, input_file_path: str, msg: str):
        """Unit testing read_csv function exceptions"""
        with pytest.raises(error) as context:
            csv_file = open(attach_path(input_file_path))
            read_csv(csv_file)
        assert str(context.value) == msg

    @pytest.mark.parametrize("error, input_file_path, msg", [
        (AssertionError, EMPTY_HASHES_DICT_JSON, "Hashes array contains no hashes"),
        (
            AssertionError,
            BASIC_JSON_WRONG_HASHLEN,
            "Found hash with 63 chars instead of 64 chars for hash: "
            "zhfsxqdiovvniajycvnnluubnsgdrqdczzarsxjoozfdbolnovnqacbtelxcnve"),
        (JSONDecodeError, BASIC_JSON_MALFORMED_FILE, "Expecting value: line 1 column 2 (char 1)")
    ])
    def test_json_exceptions(self, error, input_file_path: str, msg: str):
        """Unit testing read_json exceptions"""
        with pytest.raises(error) as context:
            with open(attach_path(input_file_path), 'r') as input_file:
                str(read_json(input_file.read()))
        assert str(context.value) == msg
