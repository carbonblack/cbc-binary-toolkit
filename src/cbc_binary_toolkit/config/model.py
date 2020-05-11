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

Model for the configuration data.
"""
import yaml
from .errors import ConfigError


class Config:
    """Config processing and management"""
    default_location = 'config/binary-analysis-config.yaml'
    _required_id = 'cbc_binary_toolkit'

    def __init__(self, data):
        """Constructor"""
        self._data = data

    @classmethod
    def load(cls, data):
        """
        Load YAML data into a Config object.

        Args:
            data: Data to be loaded. May be a string, or an open text or binary stream.

        Returns:
            (Config): The Config object that contains the data in the config file.

        """
        try:
            mydata = yaml.safe_load(data)
            if isinstance(mydata, dict):
                validation = mydata.get('id', None)
                if validation != Config._required_id:
                    raise ConfigError('Invalid configuration ID')
                validation = mydata.get('version', None)
                # TODO: do some sort of version check here
                return Config(mydata)
            else:
                raise ConfigError('Invalid configuration data format')
        except yaml.YAMLError as exc:
            message = 'Load error: ' + str(exc)
            if hasattr(exc, 'problem_mark'):
                mark = exc.problem_mark
                message = message + (' at (%s,%s)' % (mark.line + 1, mark.column + 1))
            raise ConfigError(message, exc)

    @classmethod
    def load_file(cls, filename):
        """
        Load a YAML file into a Config object.

        Args:
            filename (str): The name of the file to be loaded.

        Returns:
            (Config): The Config object that contains the data in the config file.

        """
        with open(filename, 'r') as file:
            return Config.load(file)

    def _seek_path(self, path, suppress_exceptions=False):
        """
        Seeks out a value in the configuration data with a specific path.

        Args:
            path (str): The path to the configuration variable (with components separated by '.')
            suppress_exceptions (bool): If true, None will be returned for paths that do
                not exist. If this is False, a ConfigError will be raised for paths that do not exist.

        Returns:
            The configuration value, which may be of any type.

        """
        cur = None
        elt = None
        for s in path.split('.'):
            if cur:
                cur = cur.get(elt, None)
                if not isinstance(cur, dict):
                    if not suppress_exceptions:
                        raise ConfigError('Invalid path: ' + path)
                    return None
            else:
                cur = self._data
            elt = s
        if suppress_exceptions:
            return cur.get(elt, None)
        return cur[elt]

    def string(self, path):
        """
        Returns a string configuration value from the configuration data.

        Args:
            path (str): The path to the configuration variable (with components separated by '.').

        """
        v = self._seek_path(path)
        if isinstance(v, str):
            return v
        raise ConfigError('value not string type: ' + path)

    def string_default(self, path, defaultval=None):
        """
        Returns a string configuration value from the configuration data, defaulting it if it isn't specified.

        Args:
            path (str): The path to the configuration variable (with components separated by '.').
            defaultval: The default value to use if the configuration value isn't specified (default None).

        """
        v = self._seek_path(path, True)
        if v is not None and isinstance(v, str):
            return v
        return defaultval

    def section(self, path):
        """
        Returns a sub-section of the configuration data as another Config object.

        This accesses the same data, but without the prefix. For example, if B == A.section("foo"), then
        B.string("bar") == A.string("foo.bar").

        Args:
            path (str): The path to the configuration section (with components separated by '.').

        Returns:
            (Config): The requested subsection as a new Config object.

        """
        v = self._seek_path(path)
        if isinstance(v, dict):
            return Config(v)
        raise ConfigError('value not valid section: ' + path)

    def get(self, path, defaultval=None):
        """
        Returns the desired property with the yaml property type

        Args:
            path (str): The path to the configuration variable (with components separated by '.').
            defaultval: The default value to use if the configuration value isn't specified (default None).

        """
        v = self._seek_path(path, True)
        if v is not None:
            return v
        return defaultval
