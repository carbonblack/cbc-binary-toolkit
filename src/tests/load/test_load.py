# -*- coding: utf-8 -*-

# *******************************************************
# Copyright (c) VMware, Inc. 2020-2021. All Rights Reserved.
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
import subprocess
import os

from cbc_sdk import CBCloudAPI
from cbc_sdk.enterprise_edr import Feed

LOG_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), "log.txt")

# Clear log file for each run
open(LOG_FILE, "w").close()


@pytest.fixture()
def auth_token(pytestconfig):
    """Get API token from command line"""
    return pytestconfig.getoption("token")


@pytest.fixture()
def use_shell(pytestconfig):
    """Return option as to whether to use shell when invoking subprocesses"""
    opt = pytestconfig.getoption("useshell")
    return True if opt else False


def _format_config(auth_token, feed_id):
    """Configure for most of the test cases in this module."""
    return (f"""id: cbc_binary_toolkit
version: 0.0.1
carbonblackcloud:
  url: https://defense-eap01.conferdeploy.net
  api_token: {auth_token}
  org_key: WNEXFKQ7
  ssl_verify: True
  expiration_seconds: 3600
database:
  _provider: cbc_binary_toolkit.state.builtin.Persistor
  location: ":memory:"
engine:
  name: Yara
  feed_id: {feed_id}
  type: local
  _provider: cbc_binary_toolkit_examples.engine.yara_local.yara_engine.YaraFactory
  rules_file: __file__/load_rule.yara
    """)


def _format_invalid_config(auth_token, feed_id):
    """Configure for invalid test cases in this module."""
    return (f"""id: cbc_binary_toolkit
version: 0.0.1
carbonblackcloud:
  url: https://defense-eap01.conferdeploy.net
  api_token: {auth_token}
  org_key: WNEXFKQ7
  ssl_verify: True
  expiration_seconds: 3600
database:
  _provider: cbc_binary_toolkit.state.builtin.Persistor
  location: ":memory:"
engine:
  name:
  feed_id: {feed_id}
  type: local
  _provider: cbc_binary_toolkit_examples.engine.yara_local.yara_engine.YaraFactory
  rules_file: __file__/example_rule.yara
    """)


def _create_feed(auth_token):
    """Create a Feed to use for testing"""
    cb = CBCloudAPI(url="https://defense-eap01.conferdeploy.net",
                    token=auth_token, org_key="WNEXFKQ7")
    # Feed Creation
    feedinfo = {"name": "Temporary BAT Load Test Feed", "owner": "DevRel",
                "provider_url": "https://developer.carbonblack.com", "summary": "BAT Load test feed",
                "category": "None", "access": "private"}
    feed_dict = {"feedinfo": feedinfo, "reports": []}
    feed = cb.create(Feed, feed_dict)
    feed.save()
    return feed._info


@pytest.fixture()
def create_and_write_config(auth_token):
    """Generate and write the test config to file"""
    feed_info = _create_feed(auth_token)
    feed_id = feed_info["id"]
    with open("config/load_config.yml", "w") as f:
        config_text = _format_config(auth_token, feed_id)
        f.write(config_text)
    return feed_id


@pytest.fixture()
def create_and_write_invalid_config(auth_token):
    """Generate and write the test config to file"""
    feed_info = _create_feed(auth_token)
    feed_id = feed_info["id"]
    with open("config/load_config.yml", "w") as f:
        config_text = _format_invalid_config(auth_token, feed_id)
        f.write(config_text)
    return feed_id


def get_reports_from_feed(auth_token, feed_id):
    """GET to /feed/{feed_id}/reports to verify reports were sent"""
    cb = CBCloudAPI(url="https://defense-eap01.conferdeploy.net",
                    token=auth_token, org_key="WNEXFKQ7")
    feed = cb.select(Feed, feed_id)
    results = {"results": [report._info for report in feed.reports]}
    return results


def delete_feed(auth_token, feed_id):
    """Delete Feed after it's used for testing"""
    cb = CBCloudAPI(url="https://defense-eap01.conferdeploy.net",
                    token=auth_token, org_key="WNEXFKQ7")
    feed = cb.select(Feed, feed_id)
    feed.delete()


@pytest.mark.incremental
class TestUserHandling:
    """Test users experience interacting with binary analysis commandline"""
    @pytest.mark.parametrize(["filename", "num_hashes"], [
        (["src/tests/load/fixtures/1000_hashes.csv", 1000]),
    ])
    def test_analyze_file(self, create_and_write_config, auth_token, use_shell, filename, num_hashes):
        """Test analyze command"""
        with open(LOG_FILE, "a+") as log:
            subprocess.call(['cbc-binary-analysis', '-c', 'config/load_config.yml',
                             '-ll', 'DEBUG', 'analyze', '-f', filename],
                            shell=use_shell, stdout=log, stderr=log)
            log.close()
        reports = get_reports_from_feed(auth_token, create_and_write_config)
        delete_feed(auth_token, create_and_write_config)
        assert len(reports['results'][0]["iocs_v2"]) == num_hashes
