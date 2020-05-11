# -*- coding: utf-8 -*-

# *******************************************************
# Copyright (c) VMware, Inc. 2019. All Rights Reserved.
# SPDX-License-Identifier: MIT
# *******************************************************
# *
# * DISCLAIMER. THIS PROGRAM IS PROVIDED TO YOU "AS IS" WITHOUT
# * WARRANTIES OR CONDITIONS OF ANY KIND, WHETHER ORAL OR WRITTEN,
# * EXPRESS OR IMPLIED. THE AUTHOR SPECIFICALLY DISCLAIMS ANY IMPLIED
# * WARRANTIES OR CONDITIONS OF MERCHANTABILITY, SATISFACTORY QUALITY,
# * NON-INFRINGEMENT AND FITNESS FOR A PARTICULAR PURPOSE.

"""Unit tests for the configuration code"""

import pytest
from cbc_binary_toolkit.config import Config
from cbc_binary_toolkit.config.errors import ConfigError


# ==================================== Unit TESTS BELOW ====================================


def test_load_valid_config():
    """Test the load of a valid configuration."""
    cfg = Config.load("""
    id: cbc_binary_toolkit
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
    id: cbc_binary_toolkit
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


def test_get():
    """Test the get() API."""
    cfg = Config.load("""
    id: cbc_binary_toolkit
    version: 0.0.1
    pets:
      dog: QBit
      cat: True
      tortoises: 2
    """)
    assert isinstance(cfg.get('pets.dog'), str)
    assert cfg.get('pets.dog') == "QBit"
    assert isinstance(cfg.get('pets.cat'), bool)
    assert cfg.get('pets.cat') is True
    assert isinstance(cfg.get('pets.tortoises'), int)
    assert cfg.get('pets.tortoises') == 2
    assert isinstance(cfg.get('pets.missing', True), bool)
    assert cfg.get('pets.missing', True) is True
    assert cfg.get('pets.missing') is None
