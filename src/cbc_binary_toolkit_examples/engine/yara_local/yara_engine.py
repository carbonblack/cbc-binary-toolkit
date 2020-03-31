# -*- coding: utf-8 -*-

"""Local yara engine"""

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

        if self.config.get("engine.name") != self.name:
            log.error("Attempted to init engine with non matching engine config")
            raise InitializationError

        # Compile yara rules
        self.rules = yara.compile(self.config.get("engine.rules_dir"))

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

                matches = self.rules.match(data=resp.raw.read())

                highest_severity = 0
                for match in matches["main"]:

                    if match["meta"].get("sev", 0) > highest_severity:
                        highest_severity = match["meta"].get("sev", 0)

                iocs = []
                if highest_severity > 0:
                    iocs.append({
                        "id": str(uuid.uuid4()),
                        "match_type": "equality",
                        "values": [binary_metadata["sha256"]],
                        "field": "process_hash",
                        "severity": highest_severity
                    })

                result = {
                    "iocs": iocs,
                    "engine_name": self.name,
                    "binary_hash": binary_metadata["sha256"],
                    "success": True
                }
            except Exception as e:
                log.error(f"Failed processing binary: {e}")

        if result is None:
            return {
                "iocs": [],
                "engine_name": self.name,
                "binary_hash": binary_metadata.get(["sha256"], None) if isinstance(binary_metadata, dict) else None,
                "success": False
            }
        else:
            return result
