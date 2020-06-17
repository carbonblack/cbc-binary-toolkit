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
import subprocess
import sys
import os
import requests
import csv


if sys.platform.startswith("win32"):
    pycommand = "python"
else:
    pycommand = "python3"

LOG_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), "log.txt")

# BIN = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../../bin/cbc-binary-analysis")
#
# SRC = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../../")
# Clear log file for each run
open(LOG_FILE, "w").close()


@pytest.fixture()
def auth_token(pytestconfig):
    """Get API token from command line"""
    return pytestconfig.getoption("token")


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
  rules_file: __file__/example_rule.yara
    """)


def _create_feed(auth_token):
    """Create a Feed to use for testing"""
    # Feed Creation
    url = "https://defense-eap01.conferdeploy.net/threathunter/feedmgr/v2/orgs/WNEXFKQ7/feeds"

    payload = ("{\"feedinfo\": {\"name\": \"BATFuncTest\", \"owner\": \"DevRel\","
               "\"provider_url\": \"some_url\", \"summary\": \"BAT functional testing\","
               "\"category\": \"None\"},\n \"reports\": []}\n\n\n")
    headers = {
        'X-Auth-Token': f'{auth_token}',
        'Content-type': 'application/json',
        'Content-Type': 'text/plain'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    return response.json()


@pytest.fixture()
def create_and_write_config(auth_token):
    """Generate and write the test config to file"""
    feed_info = _create_feed(auth_token)
    feed_id = feed_info["id"]
    with open("config/functional_config.yml", "w") as f:
        config_text = _format_config(auth_token, feed_id)
        f.write(config_text)
    return feed_id


def get_reports_from_feed(auth_token, feed_id):
    """GET to /feed/{feed_id}/reports to verify reports were sent"""
    url = f'https://defense-eap01.conferdeploy.net/threathunter/feedmgr/v1/feed/{feed_id}/report'
    headers = {
        'X-Auth-Token': f'{auth_token}'
    }

    response = requests.request("GET", url, headers=headers)
    print("REPORTS RESPONSE:", response.json())
    return response.json()


def delete_feed(auth_token, feed_id):
    """Delete Feed after it's used for testing"""
    url = f"https://defense-eap01.conferdeploy.net/threathunter/feedmgr/v2/orgs/WNEXFKQ7/feeds/{feed_id}"

    payload = {}
    headers = {
        'X-Auth-Token': f'{auth_token}'
    }
    response = requests.request("DELETE", url, headers=headers, data=payload)
    print(response.text.encode('utf8'))


def write_hashes_to_csv(hashes):
    """Writes hash(es) to a CSV file for testing"""
    num_hashes = str(len(hashes))
    print(type(hashes))
    print(hashes[0])
    with open(num_hashes + "_hashes.csv", "w", newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerows(hashes)
    # return file name that was created
    return num_hashes + "_hashes.csv"


@pytest.mark.incremental
class TestUserHandling:
    """Test users experience interacting with binary analysis commandline"""

    def test_analyze_cli_one_hash(self, create_and_write_config, auth_token):
        """Test analyze command"""
        with open(LOG_FILE, "a+") as log:
            subprocess.call(['cbc-binary-analysis', '-c', 'config/functional_config.yml',
                             'analyze', '-l ["405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4"]'],
                            stdout=log, stderr=log)
        reports = get_reports_from_feed(auth_token, create_and_write_config)
        assert len(reports['results'][0]["iocs_v2"]) == 1
        delete_feed(auth_token, create_and_write_config)

    def test_analyze_file_one_hash(self, create_and_write_config, auth_token):
        """Test analyze command"""
        filename = write_hashes_to_csv([["405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4"]])
        with open(LOG_FILE, "a+") as log:
            subprocess.call(['cbc-binary-analysis', '-c', 'config/functional_config.yml',
                             'analyze', '-f', filename],
                            stdout=log, stderr=log)
        reports = get_reports_from_feed(auth_token, create_and_write_config)
        assert len(reports['results'][0]["iocs_v2"]) == 1
        delete_feed(auth_token, create_and_write_config)

    def test_analyze_cli_two_hashes(self, create_and_write_config, auth_token):
        """Test analyze command with two valid hashes"""
        with open(LOG_FILE, "a+") as log:
            subprocess.call(['cbc-binary-analysis', '-c', 'config/functional_config.yml',
                             'analyze', '-l', '["405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4",'
                                              '"00a16c806ff694b64e566886bba5122655eff89b45226cddc8651df7860e4524"]'],
                            stdout=log, stderr=log)
        reports = get_reports_from_feed(auth_token, create_and_write_config)
        assert len(reports['results'][0]["iocs_v2"]) == 2
        delete_feed(auth_token, create_and_write_config)

    def test_analyze_file_two_hashes(self, create_and_write_config, auth_token):
        """Test analyze command with two valid hashes"""
        filename = write_hashes_to_csv([["405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4"],
                                        ["00a16c806ff694b64e566886bba5122655eff89b45226cddc8651df7860e4524"]])
        with open(LOG_FILE, "a+") as log:
            subprocess.call(['cbc-binary-analysis', '-c', 'config/functional_config.yml',
                             'analyze', '-f', filename],
                            stdout=log, stderr=log)
        reports = get_reports_from_feed(auth_token, create_and_write_config)
        assert len(reports['results'][0]["iocs_v2"]) == 2
        delete_feed(auth_token, create_and_write_config)

    def test_clear(self):
        """Test clear command"""
        # with open(LOG_FILE, "a+") as log:
        # subprocess.call([pycommand, BIN, 'clear'], stdout=log, stderr=log)
        pass
