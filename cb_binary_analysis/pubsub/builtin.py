# -*- coding: utf-8 -*-

"""Default implementation of the PubSub Provider that uses Python Queue structures."""


from queue import Queue
from .manager import BaseQueue, BaseProvider, BaseProviderFactory


class PythonBasedQueue(BaseQueue):
    """Default implementation of the PubSub queue."""
    def __init__(self):
        """Constructor"""
        self._queue = Queue(0)

    def put(self, workitem):
        """
        Puts a new work item on the queue.

        :param workitem dict: The work item to put on the queue.
        """
        self._queue.put(workitem, True)

    def get(self):
        """
        Retrieves a new work item from the queue.

        If there are no work items available, blocks until one becomes available.

        :return: The first work item on the queue.
        """
        return self._queue.get(True)


class PythonBasedProvider(BaseProvider):
    """Default implementation of the PubSub provider."""
    def __init__(self):
        """Constructor"""
        self._queues = {}

    def create_queue(self, queue_name):
        """
        Creates a new PubSub queue.  If one already exists by that name, returns that instance.

        :param queue_name str: The name for the new queue.
        :return: The new queue object.
        """
        rc = self._queues.get(queue_name, None)
        if rc is None:
            rc = PythonBasedQueue()
            self._queues[queue_name] = rc
        return rc

    def get_queue(self, queue_name):
        """
        Gets a PubSub queue by name.

        :param queue_name str: The name for the new queue.
        :return: The new queue object.
        """
        return self._queues.get(queue_name, None)


class Provider(BaseProviderFactory):
    """Default implementation of the PubSub provider factory."""
    def create_pubsub_provider(self, config):
        """
        Creates a new PubSub provider object.

        :param config Config: The configuration section for the persistence parameters.
        :return: The new provider factory object.
        """
        return PythonBasedProvider()
