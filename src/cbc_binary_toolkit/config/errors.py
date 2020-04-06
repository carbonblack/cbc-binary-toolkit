# -*- coding: utf-8 -*-

"""
Binary analysis sdk for managing and submitting hashes

Exceptions raised by configuration code.
"""


class ConfigError(Exception):
    """Exception thrown in the event of errors in the configuration."""
    def __init__(self, message=None, original_exception=None):
        """Constructor"""
        self.message = str(message)
        self.original_exception = original_exception

    def __str__(self):
        """Return the message associated with the exception"""
        return self.message
