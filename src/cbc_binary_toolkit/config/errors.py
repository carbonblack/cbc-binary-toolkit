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
