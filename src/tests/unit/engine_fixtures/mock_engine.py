# -*- coding: utf-8 -*-

"""Mock engine"""

from cbc_binary_toolkit.engine import LocalEngineFactory
from threading import Thread


class TestLocalEngine(Thread):
    """Mock test engine"""
    def __init__(self, group=None, target=None, name=None,
                 args=(), kwargs=None, verbose=None):
        """Yara engine thread, pulling from engine pub/sub queue"""
        super(TestLocalEngine, self).__init__(group=group, target=target, name=name)

        self.name = "MockEngine"
        self.config = kwargs.get("config", None)
        self.pub_sub_manager = kwargs.get("pub_sub_manager", None)

    def run(self):
        """Start of thread"""
        while True:
            test_data = self.pub_sub_manager.get(self.name)

            if test_data is None:
                break

            self.pub_sub_manager.put(self.config.get("pubsub.result_queue_name"), test_data)


class TestLocalEngineFactory(LocalEngineFactory):
    """Mock Factory for testing LocalEngineManager"""
    def create_engine(self, config, pub_sub_manager):
        """Create test engine"""
        return TestLocalEngine(kwargs={"config": config, "pub_sub_manager": pub_sub_manager})
