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

"""
Integration tests for binary analysis

This tests the input from the users experience
"""

import pytest
# import subprocess
import sys
import os

if sys.platform.startswith("win32"):
    pycommand = "python"
else:
    pycommand = "python3"

LOG_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), "log.txt")

BIN = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../../bin/cbc-binary-analysis")


# Clear log file for each run
open(LOG_FILE, "w").close()


@pytest.mark.incremental
class TestUserHandling:
    """Test users experience interacting with binary analysis commandline"""

    def test_analyze(self):
        """Test analyze command"""
        # with open(LOG_FILE, "a+") as log:
        # subprocess.call([pycommand, BIN, 'analyze', '-l ["test"]'], stdout=log, stderr=log)
        pass

    def test_clear(self):
        """Test clear command"""
        # with open(LOG_FILE, "a+") as log:
        # subprocess.call([pycommand, BIN, 'clear'], stdout=log, stderr=log)
        pass
