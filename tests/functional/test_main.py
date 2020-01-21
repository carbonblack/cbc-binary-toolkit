# -*- coding: utf-8 -*-

"""
Integration tests for binary analysis

This tests the input from the users experience
"""

import pytest
import subprocess

LOG_FILE = "tests/functional/log.txt"

# Clear log file for each run
open(LOG_FILE, "w").close()


@pytest.mark.incremental
class TestUserHandling:
    """Test users experience interacting with binary analysis commandline"""

    def test_analyze(self):
        """Test analyze command"""
        with open(LOG_FILE, "a+") as log:
            subprocess.call(['python3', 'cb-binary-analysis/main.py', 'analyze', '-l ["test"]'], stdout=log, stderr=log)
            pass

    def test_clear(self):
        """Test clear command"""
        with open(LOG_FILE, "a+") as log:
            subprocess.call(['python3', 'cb-binary-analysis/main.py', 'clear'], stdout=log, stderr=log)
            pass
