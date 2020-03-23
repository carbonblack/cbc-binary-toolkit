# -*- coding: utf-8 -*-

"""The high-level management for the state of analyzed files."""


from cbc_binary_toolkit.loader import dynamic_create


class BasePersistor:
    """'Abstract base class' that should be inherited by persistor objects."""
    def set_checkpoint(self, binary_hash, engine, checkpoint_name):
        """
        Set a checkpoint on a binary hash/engine combination.
        
        :param binary_hash str: The hash value to set in the database.
        :param engine str: The engine value to set in the database.
        :param checkpoint_name str: The name of the checkpoint to set.
        """
        raise NotImplementedError("protocol not implemented: set_checkpoint")
    
    def get_previous_hashes(self, engine):
        """
        Returns a sorted list of all previously-completed hashes.
        
        :param engine str: The engine value to look up in the database.
        :return: A list of all the hashes that have been marked as "done" for that engine. This list
        will be in sorted order.
        """
        raise NotImplementedError("protocol not implemented: get_previous_hashes")
    
    def get_unfinished_hashes(self, engine):
        """
        Returns a sorted list of all not-completed hashes.
        
        :param engine str: The engine value to look up in the database.
        :return: A list of all the hashes that are in the database but have not been marked as "done"
        for that engine.  This list is in the form of tuples, the first element of which is the hash,
        the second element of which is the last known checkpoint. 
        """
        raise NotImplementedError("protocol not implemented: get_unfinished_hashes")
    
    def prune(self, timestamp):
        """
        Erases all entries from the database older than a specified time.

        :param timestamp str: The basic timestamp. Everything older than this will be erased.
        """
        raise NotImplementedError("protocol not implemented: prune")

    def add_report_item(self, severity, engine, data):
        """
        Adds a new report item (IOC record) to the current stored list.

        :param severity int: The severity level (1-10).
        :param engine str: The engine value to store this data for.
        :param data dict: The data item to be stored.
        """
        raise NotImplementedError("protocol not implemented: add_report_item")

    def get_current_report_items(self, severity, engine):
        """
        Returns all current report items (IOC records) in the given list.

        :param severity int: The severity level (1-10).
        :param engine str: The engine value to return data for.
        :return: A list of dicts, each of which represents a report item.
        """
        raise NotImplementedError("protocol not implemented: get_current_report_items")

    def clear_report_items(self, severity, engine):
        """
        Clears all report items (IOC records) from a given list.

        :param severity int: The severity level (1-10).
        :param engine str: The engine value to clear data for.
        """
        raise NotImplementedError("protocol not implemented: clear_report_items")


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

    def set_checkpoint(self, binary_hash, engine, checkpoint_name):
        """
        Set a checkpoint on a binary hash/engine combination.
        
        :param binary_hash str: The hash value to set in the database.
        :param engine str: The engine value to set in the database.
        :param checkpoint_name str: The name of the checkpoint to set.
        """
        self._persistor.set_checkpoint(binary_hash, engine, checkpoint_name)
    
    def get_previous_hashes(self, engine):
        """
        Returns a sorted list of all previously-completed hashes.
        
        :param engine str: The engine value to look up in the database.
        :return: A list of all the hashes that have been marked as "done" for that engine. This list
        will be in sorted order.
        """
        return self._persistor.get_previous_hashes(engine)
    
    def get_unfinished_hashes(self, engine):
        """
        Returns a sorted list of all not-completed hashes.
        
        :param engine str: The engine value to look up in the database.
        :return: A list of all the hashes that are in the database but have not been marked as "done"
        for that engine.  This list is in the form of tuples, the first element of which is the hash,
        the second element of which is the last known checkpoint. 
        """
        return self._persistor.get_unfinished_hashes(engine)
    
    def prune(self, timestamp):
        """
        Erase all records older than a specified timestamp.

        :param timestamp str: The timestamp of the oldest records to retain in the data store.
        """
        self._persistor.prune(timestamp)

    def add_report_item(self, severity, engine, data):
        """
        Adds a new report item (IOC record) to the current stored list.

        :param severity int: The severity level (1-10).
        :param engine str: The engine value to store this data for.
        :param data dict: The data item to be stored.
        """
        self._persistor.add_report_item(severity, engine, data)

    def get_current_report_items(self, severity, engine):
        """
        Returns all current report items (IOC records) in the given list.

        :param severity int: The severity level (1-10).
        :param engine str: The engine value to return data for.
        :return: A list of dicts, each of which represents a report item.
        """
        return self._persistor.get_current_report_items(severity, engine)

    def clear_report_items(self, severity, engine):
        """
        Clears all report items (IOC records) from a given list.

        :param severity int: The severity level (1-10).
        :param engine str: The engine value to clear data for.
        """
        self._persistor.clear_report_items(severity, engine)
