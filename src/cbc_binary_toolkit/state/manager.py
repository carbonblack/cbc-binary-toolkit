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

"""The high-level management for the state of analyzed files."""


from cbc_binary_toolkit.loader import dynamic_create


class BasePersistor:
    """'Abstract base class' that should be inherited by persistor objects."""
    def force_close(self):
        """
        Forces the persistor to close. This should only be called from test code.
        """
        pass

    def set_checkpoint(self, binary_hash, engine_name, checkpoint_name, checkpoint_time=None):
        """
        Set a checkpoint on a binary hash/engine combination.

        Args:
            binary_hash (str): The hash value to set in the database.
            engine_name (str): The engine value to set in the database.
            checkpoint_name (str): The name of the checkpoint to set.
            checkpoint_time (str): The timestamp to set the checkpoint time to.  Assumed to be in
                                   local time.  Not normally used except in test code.

        """
        raise NotImplementedError("protocol not implemented: set_checkpoint")

    def get_previous_hashes(self, engine_name):
        """
        Returns a sorted list of all previously-completed hashes.

        Args:
            engine_name (str): The engine value to look up in the database.

        Returns:
            list: A list of all the hashes that have been marked as "done" for that engine. This list
            will be in sorted order.

        """
        raise NotImplementedError("protocol not implemented: get_previous_hashes")

    def get_unfinished_hashes(self, engine_name):
        """
        Returns a sorted list of all not-completed hashes.

        Args:
            engine_name (str): The engine value to look up in the database.

        Returns:
            list: A list of all the hashes that are in the database but have not been marked as "done"
            for that engine.  This list is in the form of tuples, the first element of which is the hash,
            the second element of which is the last known checkpoint.

        """
        raise NotImplementedError("protocol not implemented: get_unfinished_hashes")

    def prune(self, timestamp):
        """
        Erases all entries from the database older than a specified time.

        Args:
            timestamp (str): The basic timestamp (ISO 8601 format). Assumed to be in local time.
                              Everything older than this will be erased.

        """
        raise NotImplementedError("protocol not implemented: prune")

    def add_report_item(self, severity, engine_name, data):
        """
        Adds a new report item (IOC record) to the current stored list.

        Args:
            severity (int): The severity level (1-10).
            engine_name (str): The engine value to store this data for.
            data (dict): The data item to be stored.

        """
        raise NotImplementedError("protocol not implemented: add_report_item")

    def get_current_report_items(self, severity, engine_name):
        """
        Returns all current report items (IOC records) in the given list.

        Args:
            severity (int): The severity level (1-10).
            engine_name (str): The engine value to return data for.

        Returns:
            list: A list of dicts, each of which represents a report item.

        """
        raise NotImplementedError("protocol not implemented: get_current_report_items")

    def clear_report_items(self, severity, engine_name):
        """
        Clears all report items (IOC records) from a given list.

        Args:
            severity (int): The severity level (1-10).
            engine_name (str): The engine value to clear data for.

        """
        raise NotImplementedError("protocol not implemented: clear_report_items")


class BasePersistorFactory:
    """'Abstract base class' that should be inherited by persistor factory objects."""
    def create_persistor(self, config):
        """
        Creates a new persistor object.

        Args:
            config (Config): The configuration section for the persistence parameters.

        Returns:
            Persistor: The new persistor object.

        """
        raise NotImplementedError("protocol not implemented: create_persistor")


class StateManager:
    """
    High level manager for file state that passes through to a persistence provider.

    Initializes State Manager indicate by config
    """
    def __init__(self, config):
        """Constructor"""
        factory_classname = config.string('database._provider')
        factory = dynamic_create(factory_classname)
        self._persistor = factory.create_persistor(config.section('database'))

    def force_close(self):
        """
        Forces the persistor to close. This should only be called from test code.
        """
        self._persistor.force_close()
        self._persistor = None

    def set_checkpoint(self, binary_hash, engine_name, checkpoint_name, checkpoint_time=None):
        """
        Set a checkpoint on a binary hash/engine combination.

        Args:
            binary_hash (str): The hash value to set in the database.
            engine_name (str): The engine value to set in the database.
            checkpoint_name (str): The name of the checkpoint to set.
            checkpoint_time (str): The timestamp to set the checkpoint time to.  Assumed to be in
                                   local time.  Not normally used except in test code.

        """
        self._persistor.set_checkpoint(binary_hash, engine_name, checkpoint_name, checkpoint_time)

    def get_previous_hashes(self, engine_name):
        """
        Returns a sorted list of all previously-completed hashes.

        Args:
            engine_name (str): The engine value to look up in the database.

        Returns:
            list: A list of all the hashes that have been marked as "done" for that engine. This list
                  will be in sorted order.

        """
        return self._persistor.get_previous_hashes(engine_name)

    def get_unfinished_hashes(self, engine_name):
        """
        Returns a sorted list of all not-completed hashes.

        Args:
            engine_name (str): The engine value to look up in the database.

        Returns:
            list: A list of all the hashes that are in the database but have not been marked as "done"
                  for that engine.  This list is in the form of tuples, the first element of which is
                  the hash, the second element of which is the last known checkpoint.

        """
        return self._persistor.get_unfinished_hashes(engine_name)

    def prune(self, timestamp):
        """
        Erases all entries from the database older than a specified time.

        Args:
            timestamp (str): The basic timestamp (ISO 8601 format). Assumed to be in local time.
                             Everything older than this will be erased.

        """
        self._persistor.prune(timestamp)

    def add_report_item(self, severity, engine_name, data):
        """
        Adds a new report item (IOC record) to the current stored list.

        Args:
            severity (int): The severity level (1-10).
            engine_name (str): The engine value to store this data for.
            data (dict): The data item to be stored.

        """
        self._persistor.add_report_item(severity, engine_name, data)

    def get_current_report_items(self, severity, engine_name):
        """
        Returns all current report items (IOC records) in the given list.

        Args:
            severity (int): The severity level (1-10).
            engine_name (str): The engine value to return data for.

        Returns:
            list: A list of dicts, each of which represents a report item.

        """
        return self._persistor.get_current_report_items(severity, engine_name)

    def clear_report_items(self, severity, engine_name):
        """
        Clears all report items (IOC records) from a given list.

        Args:
            severity (int): The severity level (1-10).
            engine_name (str): The engine value to clear data for.

        """
        self._persistor.clear_report_items(severity, engine_name)
