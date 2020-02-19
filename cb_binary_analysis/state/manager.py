# -*- coding: utf-8 -*-

"""The high-level management for the state of analyzed files."""


from cb_binary_analysis.loader import dynamic_create


class BasePersistor:
    """'Abstract base class' that should be inherited by persistor objects."""
    def get_file_state(self, binary_hash, engine=None):
        """
        Get the stored file state for a specified hash value.

        :param binary_hash str: The hash value to look up in the database.
        :param engine str: (Optional) The engine value to look up in the database.
        :return: A dict containing the file information, or None if not found.
        """
        raise NotImplementedError("protocol not implemented: get_file_state")

    def set_file_state(self, binary_hash, attrs, persist_id=None):
        """
        Set the stored file state for a specified hash value.

        :param binary_hash str: The hash value to set in the database.
        :param attrs dict: The attributes to set as part of the hash value entry.
        :param persist_id int: The persistence ID of the existing record we're modifying (optional).
        :return: The persistence ID of the database row, either new or existing.
        """
        raise NotImplementedError("protocol not implemented: set_file_state")

    def prune(self, timestamp):
        """
        Erases all entries from the database older than a specified time.

        :param timestamp str: The basic timestamp. Everything older than this will be erased.
        """
        raise NotImplementedError("protocol not implemented: prune")


class BasePersistorFactory:
    """'Abstract base class' that should be inherited by persistor factory objects."""
    def create_persistor(self, config):
        """
        Creates a new persistor object.

        :param config Config: The configuration section for the persistence parameters.
        :return: The new persistor object.
        """
        raise NotImplementedError("protocol not implemented: create_persistor")


class StateManager:
    """
    High level manager for file state that passes through to a persistence provider.

    Initializes State Manager indicate by config
    """
    def __init__(self, config):
        """Constuctor"""
        factory_classname = config.string('database._provider')
        factory = dynamic_create(factory_classname)
        self._persistor = factory.create_persistor(config.section('database'))

    def lookup(self, binary_hash, engine=None):
        """
        Look up the most recent record for a file by hash value.

        :param binary_hash str: The hash value to be looked up.
        :param engine str: (Optional) The engine name to look up the information for.
        :return dict: A dict containing information about the file.  If no such record exists, returns None.
        """
        return self._persistor.get_file_state(binary_hash, engine)

    def prune(self, timestamp):
        """
        Erase all records older than a specified timestamp.

        :param timestamp str: The timestamp of the oldest records to retain in the data store.
        """
        self._persistor.prune(timestamp)

    # AGRB 1/30/2020 - the following method is just a pass-through to the lower-level persistor.
    # If it is needful to do some more adapting at the manager level it can be rewritten.

    def set_file_state(self, binary_hash, attrs, rowid=None):
        """
        Set the stored file state for a specified hash value.

        :param binary_hash str: The hash value to set in the database.
        :param attrs dict: The attributes to set as part of the hash value entry.
        :param rowid int: The row ID of the existing record we're modifying (optional).
        :return: The row ID of the database row, either new or existing.
        """
        return self._persistor.set_file_state(binary_hash, attrs, rowid)
