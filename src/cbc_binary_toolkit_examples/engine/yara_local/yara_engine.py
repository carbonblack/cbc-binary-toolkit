# -*- coding: utf-8 -*-

"""Local yara engine"""

import logging
import requests
import uuid
import yara

from threading import Thread
from cbc_binary_toolkit import InitializationError
from cbc_binary_toolkit.engine import LocalEngineFactory
log = logging.getLogger(__name__)


class YaraFactory(LocalEngineFactory):
    """Yara Factory"""
    def create_engine(self, config, pub_sub_manager):
        """Create yara engine thread"""
        return YaraEngine(kwargs={"config": config, "pub_sub_manager": pub_sub_manager})


class YaraEngine(Thread):
    """Local yara engine"""
    def __init__(self, group=None, target=None, name=None,
                 args=(), kwargs=None, verbose=None):
        """Engine Results processing thread, pulling from results pub/sub queue"""
        super(YaraEngine, self).__init__(group=group, target=target, name=name)
        """Constructor"""
        self.name = "Yara"
        self.config = kwargs.get("config", None)
        self.pub_sub_manager = kwargs.get("pub_sub_manager", None)
        self.result_queue_name = self.config.get("pubsub.result_queue_name")

        if self.config.get("engine.name") != self.name:
            log.error("Attempted to init engine with non matching engine config")
            raise InitializationError

        # Compile yara rules
        self.rules = yara.compile(self.config.get("engine.rules_dir"))

    def run(self):
        """Start of thread"""
        while True:
            binary_metadata = self.pub_sub_manager.get(self.name)

            if binary_metadata is None:
                log.debug("Exiting YaraEngine Thread")
                break
            try:
                resp = requests.get(binary_metadata["url"], stream=True)
                resp.raise_for_status()

                matches = self.rules.match(data=resp.raw.read())

                """
                {
                  'tags': ['foo', 'bar'],
                  'matches': True,
                  'namespace': 'default',
                  'rule': 'my_rule',
                  'meta': {},
                  'strings': [(81L, '$a', 'abc'), (141L, '$b', 'def')]
                }
                """

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

                self.pub_sub_manager.put(self.result_queue_name, {
                    "iocs": iocs,
                    "engine_name": self.name,
                    "binary_hash": binary_metadata["sha256"],
                    "success": True
                })
            except Exception as e:
                log.error(f"Failed processing binary: {e}")
                self.pub_sub_manager.put(self.result_queue_name, {
                    "iocs": [],
                    "engine_name": self.name,
                    "binary_hash": binary_metadata["sha256"],
                    "success": False
                })
