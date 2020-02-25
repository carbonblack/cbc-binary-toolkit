# -*- coding: utf-8 -*-

"""Unit tests for the configuration code"""

import pytest
from cbc_binary_sdk.config import Config
from cbc_binary_sdk.config.errors import ConfigError


def test_load_valid_config():
    """Test the load of a valid configuration."""
    cfg = Config.load("""
    id: cb-binary-analysis
    version: 0.0.1
    orville:
      captain: Ed Mercer
      doctor: Claire Finn
    enterprise:
      captain: Jim Kirk
      doctor: Leonard McCoy
    voyager:
      captain: Kathryn Janeway
      doctor: EMH
    """)
    assert cfg.string('orville.captain') == "Ed Mercer"
    assert cfg.string('orville.doctor') == "Claire Finn"
    assert cfg.string('enterprise.captain') == "Jim Kirk"
    assert cfg.string('enterprise.doctor') == "Leonard McCoy"
    assert cfg.string('voyager.captain') == "Kathryn Janeway"
    assert cfg.string('voyager.doctor') == "EMH"


def test_load_errors():
    """Test various load errors in the configuration."""
    with pytest.raises(ConfigError, match=r"^Invalid configuration data format"):
        Config.load("""
        - alpha
        - bravo
        - charlie
        """)
    with pytest.raises(ConfigError, match=r"^Invalid configuration ID"):
        Config.load("""
        values:
          this: A
          that: B
        """)
    with pytest.raises(ConfigError, match=r"^Invalid configuration ID"):
        Config.load("""
        id: something-weird
        version: 0
        values:
          this: A
          that: B
        """)


def test_section():
    """Test the section() API."""
    cfg = Config.load("""
    id: cb-binary-analysis
    version: 0.0.1
    pets:
      dog: QBit
      cat: Penny
      tortoise: Homer
    """)
    sect = cfg.section('pets')
    assert sect.string('dog') == cfg.string('pets.dog')
    assert sect.string('cat') == cfg.string('pets.cat')
    assert sect.string('tortoise') == cfg.string('pets.tortoise')
