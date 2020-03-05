# -*- coding: utf-8 -*-

"""Local analysis engine manager"""

from cbc_binary_toolkit import InitializationError
from cbc_binary_toolkit.loader import dynamic_create


class LocalEngineFactory():
    """Abstract base class that should be inherited by Engine Factory objects."""
    def create_engine(self, config, pub_sub_manager):
        """
        Creates a new Engine thread

        Args:
            config (cbc_binary_toolkit.Config): cbc_binary_toolkit Config object
            pub_sub_manager (cbc_binary_toolkit.PubSubManager): cbc_binary_toolkit PubSubManager

        """
        raise NotImplementedError("protocol not implemented: create_engine")


class LocalEngineManager():
    """
    High level manager for Analysis Engines that passes through to Engine threads

    Initializes and manages the threaded analysis engines
    """

    def __init__(self, config, pub_sub_manager):
        """Constructor"""
        self.config = config
        self.pub_sub_manager = pub_sub_manager

        if not self.config.get("engine.local") or self.config.get("engine.num_threads") < 1:
            raise InitializationError

        self.num_threads = self.config.get("engine.num_threads")
        self.engine_factory = dynamic_create(self.config.string("engine._provider"))

        self.threads = []
        for n in range(self.num_threads):
            self.threads.append(self.engine_factory.create_engine(self.config, self.pub_sub_manager))

    def start(self):
        """Starts engine threads"""
        for t in self.threads:
            t.start()

    def stop(self):
        """Stops engine threads"""
        for i in range(self.num_threads):
            self.pub_sub_manager.put(self.config.string("engine.name"), None)
        for t in self.threads:
            t.join()
