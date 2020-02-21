# -*- coding: utf-8 -*-

"""Configuration code for testcases"""

import pytest


def pytest_runtest_makereport(item, call):
    """Adds reports for custom pytest markers"""
    if "incremental" in item.keywords:
        if call.excinfo is not None:
            parent = item.parent
            parent._previousfailed = item


def pytest_runtest_setup(item):
    """Setup for custom pytest markers"""
    if "incremental" in item.keywords:
        previousfailed = getattr(item.parent, "_previousfailed", None)
        if previousfailed is not None:
            pytest.xfail("previous test failed ({})".format(previousfailed.name))
