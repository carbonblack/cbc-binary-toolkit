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
# import os

from cbapi.psc.threathunter import Feed, CbThreatHunterAPI

# LOG_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), "log.txt")
LOG_FILE = "./log.txt"

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
    cb = CbThreatHunterAPI(url="https://defense-eap01.conferdeploy.net",
                           token=auth_token, org_key="WNEXFKQ7")
    # Feed Creation
    feedinfo = {"name": "Temporary BAT Func Test Feed", "owner": "DevRel",
                "provider_url": "https://developer.carbonblack.com", "summary": "BAT functional test feed",
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
    with open("config/functional_config.yml", "w") as f:
        config_text = _format_config(auth_token, feed_id)
        f.write(config_text)
    return feed_id


@pytest.fixture()
def create_and_write_invalid_config(auth_token):
    """Generate and write the test config to file"""
    feed_info = _create_feed(auth_token)
    feed_id = feed_info["id"]
    with open("config/functional_config.yml", "w") as f:
        config_text = _format_invalid_config(auth_token, feed_id)
        f.write(config_text)
    return feed_id


def get_reports_from_feed(auth_token, feed_id):
    """GET to /feed/{feed_id}/reports to verify reports were sent"""
    cb = CbThreatHunterAPI(url="https://defense-eap01.conferdeploy.net",
                           token=auth_token, org_key="WNEXFKQ7")
    feed = cb.select(Feed, feed_id)
    results = {"results": [report._info for report in feed.reports]}
    return results


def delete_feed(auth_token, feed_id):
    """Delete Feed after it's used for testing"""
    cb = CbThreatHunterAPI(url="https://defense-eap01.conferdeploy.net",
                           token=auth_token, org_key="WNEXFKQ7")
    feed = cb.select(Feed, feed_id)
    feed.delete()


@pytest.mark.incremental
class TestUserHandling:
    """Test users experience interacting with binary analysis commandline"""
    @pytest.mark.parametrize(["input_list", "num_hashes"], [
        (['[]', 0]),
        (['["405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4"]', 1]),
        (['["405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4",'
          '"00a16c806ff694b64e566886bba5122655eff89b45226cddc8651df7860e4524"]', 2])
    ])
    def test_analyze_cli(self, create_and_write_config, auth_token, input_list, num_hashes):
        """Test analyze command"""
        with open(LOG_FILE, "a+") as log:
            subprocess.call(['cbc-binary-analysis', '-c', 'config/functional_config.yml',
                             '-ll', 'DEBUG', 'analyze', '-l', input_list],
                            stdout=log, stderr=log)
        reports = get_reports_from_feed(auth_token, create_and_write_config)
        if num_hashes == 0:
            assert len(reports['results']) == 0
        else:
            assert len(reports['results'][0]["iocs_v2"]) == num_hashes
        delete_feed(auth_token, create_and_write_config)

    @pytest.mark.parametrize(["filename", "num_hashes"], [
        (["src/tests/functional/fixtures/empty.csv", 0]),
        (["src/tests/functional/fixtures/one_hash.csv", 1]),
        (["src/tests/functional/fixtures/two_hashes.csv", 2])
    ])
    def test_analyze_file(self, create_and_write_config, auth_token, filename, num_hashes):
        """Test analyze command"""
        with open(LOG_FILE, "a+") as log:
            subprocess.call(['cbc-binary-analysis', '-c', 'config/functional_config.yml',
                             '-ll', 'DEBUG', 'analyze', '-f', filename],
                            stdout=log, stderr=log)
        reports = get_reports_from_feed(auth_token, create_and_write_config)
        if num_hashes == 0:
            assert len(reports['results']) == 0
        else:
            assert len(reports['results'][0]["iocs_v2"]) == num_hashes
        delete_feed(auth_token, create_and_write_config)

    @pytest.mark.parametrize(["input_file", "num_hashes"], [
        (["src/tests/functional/fixtures/112_hashes.csv", 112])
    ])
    def test_analyze_file_large(self, create_and_write_config, auth_token, input_file, num_hashes):
        """Test analyze command"""
        with open(LOG_FILE, "a+") as log:
            subprocess.call(['cbc-binary-analysis', '-c', 'config/functional_config.yml',
                             '-ll', 'DEBUG', 'analyze', '-f', input_file],
                            stdout=log, stderr=log)
        reports = get_reports_from_feed(auth_token, create_and_write_config)
        assert len(reports['results'][0]["iocs_v2"]) == num_hashes
        delete_feed(auth_token, create_and_write_config)

    @pytest.mark.parametrize(["input_list", "num_hashes"], [
        (['["405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4"]', 1]),
        (['["405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4",'
          '"00a16c806ff694b64e566886bba5122655eff89b45226cddc8651df7860e4524"]', 2])
    ])
    def test_clear(self, create_and_write_config, auth_token, input_list, num_hashes):
        """Test clear command. Feed should have two reports with `num_hashes` IOC_V2s"""
        with open(LOG_FILE, "a+") as log:
            subprocess.call(['cbc-binary-analysis', '-c', 'config/functional_config.yml',
                             'analyze', '-l', input_list],
                            stdout=log, stderr=log)
        reports = get_reports_from_feed(auth_token, create_and_write_config)
        assert len(reports['results'][0]["iocs_v2"]) == num_hashes
        with open(LOG_FILE, "a+") as log:
            subprocess.call(['cbc-binary-analysis', 'clear', '--force'], stdout=log, stderr=log)
            subprocess.call(['cbc-binary-analysis', '-c', 'config/functional_config.yml',
                             '-ll', 'DEBUG', 'analyze', '-l', input_list],
                            stdout=log, stderr=log)
        reports = get_reports_from_feed(auth_token, create_and_write_config)
        num_reports = len(reports['results'])
        for result in reports['results']:
            assert len(result['iocs_v2']) == num_hashes
        assert num_reports == 2
        delete_feed(auth_token, create_and_write_config)

    def test_invalid_configuration(self, create_and_write_invalid_config, auth_token):
        """Test running cbc-binary-analysis with invalid config"""
        with open(LOG_FILE, "a+") as log:
            subprocess.call(['cbc-binary-analysis', '-c', 'config/nonexistant_file',
                             '-ll', 'DEBUG', 'analyze', '-l',
                             '["405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4"]'],
                            stdout=log, stderr=log)

        with open(LOG_FILE, "r") as log:
            assert log.readlines()[-2].strip() == ("FileNotFoundError: [Errno 2] No such"
                                                   " file or directory: 'config/nonexistant_file'")
        delete_feed(auth_token, create_and_write_invalid_config)

    def test_invalid_configuration_1(self, create_and_write_invalid_config, auth_token):
        """Test running cbc-binary-analysis with invalid config"""
        with open(LOG_FILE, "a+") as log:
            subprocess.call(['cbc-binary-analysis', '-c', 'config/functional_config.yml',
                             '-ll', 'DEBUG', 'analyze', '-l',
                             '["405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4"]'],
                            stdout=log, stderr=log)
        with open(LOG_FILE, "r") as log:
            log = log.readlines()
            assert log[-3].strip() == ("cbc_binary_toolkit.errors.InitializationError")

            assert log[-13].strip() == ("ERROR:cbc_binary_toolkit_examples.tools.analysis_util:Failed"
                                        " to create Local Engine Manager. Check your configuration")
        delete_feed(auth_token, create_and_write_invalid_config)
