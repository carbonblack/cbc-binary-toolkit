# -*- coding: utf-8 -*-

"""
Unit tests for binary analysis

This tests the functionality of each segment of the code
"""

import pytest
from cb_binary_analysis.main import parse_args


@pytest.mark.parametrize("command,expected", [
    (['analyze', '-l', '["test"]'], 'analyze'),
    (['analyze', '--file', 'VERSION'], 'analyze'),
    (['clear'], 'clear')
])
def test_parse_args_valid(command, expected):
    """Test arg parser configuration with valid inputs"""
    args = parse_args(command)
    assert args.command_name == expected


@pytest.mark.parametrize("command, expected", [
    (['bad'], "invalid choice: 'bad'"),
    (['analyze'], "error: one of the arguments"),
    (['analyze', '-l', '["test"]', '--file', 'VERSION'],
        "error: argument -f/--file: not allowed with argument -l/--list"),
])
def test_parse_args_invalid(command, expected, capsys):
    """Test arg parser configuration with invalid inputs"""
    with pytest.raises(SystemExit):
        parse_args(command)
    captured = capsys.readouterr()
    assert expected in captured.err
