# -*- coding: utf-8 -*-

"""
Binary analysis sdk for managing and submitting hashes

Exceptions raised by configuration code.
"""

class ConfigError(Exception):
    def __init__(self, message=None, original_exception=None):
        self.message = str(message)
        self.original_exception = original_exception
        
    def __str__(self):
        return self.message
    