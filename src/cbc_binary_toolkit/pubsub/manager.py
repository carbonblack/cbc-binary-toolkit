# -*- coding: utf-8 -*-

"""The high-level management for the PubSub queue system."""


from cbc_binary_toolkit.loader import dynamic_create


class BaseQueue:
    """'Abstract base class' that should be inherited by PubSub queue objects."""
    def put(self, workitem):
        """
        Puts a new work item on the queue.

        :param workitem dict: The work item to put on the queue.
        """
        raise NotImplementedError("protocol not implemented: put")

    def get(self):
        """
        Retrieves a new work item from the queue.

        If there are no work items available, blocks until one becomes available.

        :return: The first work item on the queue.
        """
        raise NotImplementedError("protocol not implemented: get")


class BaseProvider:
    """'Abstract base class' that should be inherited by PubSub provider objects."""
    def create_queue(self, queue_name):
        """
        Creates a new PubSub queue.  If one already exists by that name, returns that instance.

        :param queue_name str: The name for the new queue.
        :return: The new queue object.
        """
        raise NotImplementedError("protocol not implemented: create_queue")

    def get_queue(self, queue_name):
        """
        Gets a PubSub queue by name.

        :param queue_name str: The name for the new queue.
        :return: The new queue object.
        """
        raise NotImplementedError("protocol not implemented: get_queue")


class BaseProviderFactory:
    """'Abstract base class' that should be inherited by PubSub provider factory objects."""
    def create_pubsub_provider(self, config):
        """
        Creates a new PubSub provider object.

        :param config Config: The configuration section for the persistence parameters.
        :return: The new provider factory object.
        """
        raise NotImplementedError("protocol not implemented: create_pubsub_provider")


class PubSubManager:
    """
    High level manager for PubSub operations that passes through to a PubSub provider.

    Initializes Pub Sub indicate by config
    """
    def __init__(self, config):
        """Constructor"""
        factory_classname = config.string('pubsub._provider')
        factory = dynamic_create(factory_classname)
        self._provider = factory.create_pubsub_provider(config.section('pubsub'))

    def create_queue(self, queue_name):
        """
        Creates a new PubSub queue.  If one already exists by that name, returns that instance.

        :param queue_name str: The name for the new queue.
        :return: The new queue object.
        """
        return self._provider.create_queue(queue_name)

    def get_queue(self, queue_name):
        """
        Gets a PubSub queue by name.

        :param queue_name str: The name for the new queue.
        :return: The new queue object.
        """
        return self._provider.get_queue(queue_name)

    def get(self, queue_name):
        """
        Gets item from queue by queue_name

        :param queue_name str: The name for the new queue.
        :return: Item from queue.
        """
        return self._provider.get_queue(queue_name).get()

    def put(self, queue_name, data):
        """
        Puts item onto queue by queue_name

        :param queue_name str: The name for the new queue.
        :param data anything: Item to put in the queue
        """
        self._provider.get_queue(queue_name).put(data)
