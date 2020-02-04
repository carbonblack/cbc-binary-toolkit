# -*- coding: utf-8 -*-

"""The high-level management for the state of analyzed files."""


from cb_binary_analysis.loader import dynamic_create


class StateManager:
    """
    High level manager for file state that passes through to a persistence provider (configured in
    the config file) to do its work.
    """
    def __init__(self, config):
        factory_classname = config.string('database._provider')
        factory = dynamic_create(factory_classname)
        self._persistor = factory.create_persistor(config.section('database'))

    def lookup(self, hashval):
        """
        Look up the most recent record for a file by hash value.

        :param hashval str: The hash value to be looked up.
        :return dict: A dict containing information about the file.  If no such record exists, returns None.
        """
        return self._persistor.get_file_state(hashval)

    def prune(self, timestamp):
        """
        Erase all records older than a specified timestamp.

        :param timestamp str: The timestamp of the oldest records to retain in the data store.
        """
        self._persistor.prune(timestamp)

    # AGRB 1/30/2020 - the following method is just a pass-through to the lower-level persistor.
    # If it is needful to do some more adapting at the manager level it can be rewritten.

    def set_file_state(self, hashval, attrs, rowid=None):
        """
        Set the stored file state for a specified hash value.

        :param hashval str: The hash value to set in the database.
        :param attrs dict: The attributes to set as part of the hash value entry.
        :param rowid int: The row ID of the existing record we're modifying (optional).
        :return: The row ID of the database row, either new or existing.
        """
        return self._persistor.set_file_state(hashval, attrs, rowid)
