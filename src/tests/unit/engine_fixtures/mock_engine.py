# -*- coding: utf-8 -*-

"""Mock engine"""

from cbc_binary_toolkit.engine import LocalEngineFactory


class MockLocalEngine():
    """Mock test engine"""
    def __init__(self, config):
        """Test engine"""
        self.name = "MockEngine"
        self.config = config

    def analyze(self, test_data):
        """Analyze test data"""
        if not isinstance(test_data, dict):
            return {
                "iocs": [],
                "engine_name": self.name,
                "binary_hash": None,
                "success": False
            }

        return {
            "iocs": [],
            "engine_name": self.name,
            "binary_hash": test_data.get("sha256", None),
            "success": True
        }


class MockLocalEngineFactory(LocalEngineFactory):
    """Mock Factory for testing LocalEngineManager"""
    def create_engine(self, config):
        """Create test engine"""
        return MockLocalEngine(config)
