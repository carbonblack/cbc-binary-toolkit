# -*- coding: utf-8 -*-

"""Test code local yara engine."""
import os
import pytest

from cbc_binary_toolkit.config import Config
from cbc_binary_toolkit.engine import LocalEngineManager
from cbc_binary_toolkit.errors import InitializationError


def attach_path(path):
    """Attaches local file path to location"""
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), path)


@pytest.fixture(scope="session")
def config():
    """Configuration for all the test cases in this module."""
    return Config.load(f"""
    id: cbc_binary_toolkit
    version: 0.0.1
    engine:
      name: Yara
      feed_id: example-feed-id
      type: local
      _provider: cbc_binary_toolkit_examples.engine.yara_local.yara_engine.YaraFactory
      rules_file: {attach_path("yara_local_fixtures/test_rule.yara")}
    """)


@pytest.fixture(scope="session")
def engine(config):
    """Yara Engine"""
    manager = LocalEngineManager(config)
    return manager.engine


@pytest.mark.parametrize("file, expected_output", [
    ("yara_local_fixtures/matching_binary",
        {
            'iocs': [{
                     'id': 'UUID',
                     'match_type': 'equality',
                     'values': ['SHA256_HASH'],
                     'field': 'process_hash',
                     'severity': 2}],
            'engine_name': 'Yara',
            'binary_hash': 'SHA256_HASH',
            'success': True}),
    ("yara_local_fixtures/nonmatching_binary",
        {
            'iocs': [],
            'engine_name': 'Yara',
            'binary_hash': 'SHA256_HASH',
            'success': True})
])
def test_match(engine, file, expected_output):
    """Tests match and report generation logic"""
    result = engine._match("SHA256_HASH", open(attach_path(file), "r"))

    if len(result.get("iocs", [])) > 0:
        result["iocs"][0]["id"] = "UUID"
    assert result == expected_output


@pytest.mark.parametrize("input, expected_output", [
    ("INVALID",
        {
            'iocs': [],
            'engine_name': 'Yara',
            'binary_hash': None,
            'success': False})
])
def test_analyze_invalid_input(engine, input, expected_output):
    """Tests match and report generation logic"""
    result = engine.analyze(input)
    assert result == expected_output


@pytest.mark.parametrize("config_text, exception", [
    (f"""
        id: cbc_binary_toolkit
        version: 0.0.1
        engine:
        name: INVALID
        feed_id: example-feed-id
        type: local
        _provider: cbc_binary_toolkit_examples.engine.yara_local.yara_engine.YaraFactory
        rules_file: {attach_path("yara_local_fixtures/test_rule.yara")}
        """, InitializationError),
    ("""
        id: cbc_binary_toolkit
        version: 0.0.1
        engine:
        name: YARA
        feed_id: example-feed-id
        type: local
        _provider: cbc_binary_toolkit_examples.engine.yara_local.yara_engine.YaraFactory
        """, InitializationError)
])
def test_invalid_config(config_text, exception):
    """Test invalid initialization"""
    with pytest.raises(exception):
        LocalEngineManager(Config.load(config_text))
