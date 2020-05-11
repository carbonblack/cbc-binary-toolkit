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

"""Test code for the dynamic loading functions."""


import pytest
from cbc_binary_toolkit.loader import dynamic_load, dynamic_create


class TestClassForLoad:
    """Stub class to be used as a target for loading operations."""
    pass

# ==================================== Unit TESTS BELOW ====================================


def test_dynamic_load():
    """Test to make sure we can dynamically load a class."""
    class1 = dynamic_load('test_loader.TestClassForLoad')
    assert class1 == TestClassForLoad
    with pytest.raises(ImportError):
        dynamic_load('bogus_package.bogus_class')


def test_dynamic_create():
    """Test to make sure we can dynamically load a class and create an instance of said class."""
    obj1 = dynamic_create('test_loader.TestClassForLoad')
    assert isinstance(obj1, TestClassForLoad)
    with pytest.raises(ImportError):
        dynamic_create('bogus_package.bogus_class')
