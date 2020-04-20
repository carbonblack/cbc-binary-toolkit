# -*- coding: utf-8 -*-

"""Mock engine"""

import copy
from cbc_binary_toolkit.engine import LocalEngineFactory


class MockLocalEngine():
    """Mock test engine"""
    def __init__(self, config):
        """Test engine"""
        self.name = "MockEngine"
        self.config = config
        self.mock_return_data = {}

    def analyze(self, test_data):
        """Analyze test data"""
        if not isinstance(test_data, dict):
            return {
                "iocs": [],
                "engine_name": self.name,
                "binary_hash": None,
                "success": False
            }

        input_hash = test_data.get("sha256", None)
        if input_hash is None:
            return_iocs = []
        else:
            return_iocs = self.mock_return_data.get(input_hash, [])
        return {
            "iocs": return_iocs,
            "engine_name": self.name,
            "binary_hash": input_hash,
            "success": True
        }

    def mock_engine_output(self, input_hash, return_iocs):
        """Set up the mock engine to return a specific set of IOCs"""
        self.mock_return_data[input_hash] = copy.deepcopy(return_iocs)


class MockLocalEngineFactory(LocalEngineFactory):
    """Mock Factory for testing LocalEngineManager"""
    def create_engine(self, config):
        """Create test engine"""
        return MockLocalEngine(config)
