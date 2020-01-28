# -*- coding: utf-8 -*-

"""
Unit tests for binary analysis

This tests the functionality of each segment of the code
"""

import pytest
from cb_binary_analysis.main import parse_args
from cb_binary_analysis.config.model import Config


@pytest.mark.parametrize("command,expected,expected_config", [
    (['analyze', '-l', '["test"]'], 'analyze', Config.default_location),
    (['analyze', '--file', 'VERSION'], 'analyze', Config.default_location),
    (['--config', 'myfile.yaml', 'analyze', '--file', 'VERSION'], 'analyze', 'myfile.yaml'),
    (['-C', 'bummer.yaml', 'analyze', '--file', 'VERSION'], 'analyze', 'bummer.yaml'),
    (['clear'], 'clear', Config.default_location)
])
def test_parse_args_valid(command, expected, expected_config):
    """Test arg parser configuration with valid inputs"""
    args = parse_args(command)
    assert args.command_name == expected
    assert args.config == expected_config


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
