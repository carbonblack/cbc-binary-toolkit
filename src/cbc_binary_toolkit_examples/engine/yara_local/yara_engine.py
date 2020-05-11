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

"""Local yara engine"""

import os
import logging
import requests
import uuid
import yara

from cbc_binary_toolkit import InitializationError
from cbc_binary_toolkit.engine import LocalEngineFactory
log = logging.getLogger(__name__)


class YaraFactory(LocalEngineFactory):
    """Yara Factory"""
    def create_engine(self, config):
        """Creates yara engine threads"""
        return YaraEngine(config)


class YaraEngine():
    """Local yara engine"""
    def __init__(self, config):
        """Yara engine thread, pulling from engine pub/sub queue"""
        self.name = "Yara"
        self.config = config

        if self.config.get("name") != self.name:
            log.error("Attempted to init engine with non matching engine config")
            raise InitializationError

        if self.config.get("rules_file") is None:
            log.error("Attempted to init engine without rules file")
            raise InitializationError

        rule_path = self.config.get("rules_file")
        if "__file__" in rule_path:
            rule_path = rule_path.replace("__file__", os.path.dirname(os.path.realpath(__file__)))

        # Compile yara rules
        self.rules = yara.compile(filepath=rule_path)

    def _match(self, hash, stream):
        """
        Matches binary with loaded rules

        Args:
            hash (str): The sha256 hash to be included in the report
            stream (i/o stream): Input stream of the binary

        """
        matches = self.rules.match(data=stream.read())

        highest_severity = 0
        for match in matches:
            if match.meta.get("sev", 0) > highest_severity:
                highest_severity = match.meta.get("sev", 0)

        iocs = []
        if highest_severity > 0:
            iocs.append({
                "id": str(uuid.uuid4()),
                "match_type": "equality",
                "values": [hash],
                "field": "process_hash",
                "severity": highest_severity
            })

        return {
            "iocs": iocs,
            "engine_name": self.name,
            "binary_hash": hash,
            "success": True
        }

    def analyze(self, binary_metadata):
        """
        Analyze the binary

        Args:
            binary_metadata (dict): The binary metadata to be analyzed

        Returns:
            EngineResponseSchema: Results from analzying the binary

        """
        result = None
        if not isinstance(binary_metadata, dict):
            log.error(f"Recieved unexpected input: {type(binary_metadata)}")
        else:
            try:
                resp = requests.get(binary_metadata["url"], stream=True)
                resp.raise_for_status()

                result = self._match(binary_metadata["sha256"], resp.raw)
            except Exception as e:
                log.error(f"Failed processing binary: {e}")

        if result is None:
            return {
                "iocs": [],
                "engine_name": self.name,
                "binary_hash": binary_metadata.get("sha256", None) if isinstance(binary_metadata, dict) else None,
                "success": False
            }
        else:
            return result
