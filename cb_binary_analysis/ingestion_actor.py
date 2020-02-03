# -*- coding: utf-8 -*-

"""Base for ingestion actor"""

import logging

from thespian.actors import Actor, ActorExitRequest
from queue import Queue
from threading import Thread
from types import MethodType
from datetime import datetime

log = logging.getLogger(__name__)
log.disabled = False


def worker(queue: Queue, func: MethodType):
    """
    Generic Worker

    Args:
        queue (Queue): The queue to fetch tasks
        func (MethodType): The method to perform work on the task

    """
    while True:
        item = queue.get()
        if item is None:
            break
        func(item)
        queue.task_done()


class IngestionActor(Actor):
    """IngestionActor"""

    num_worker_threads = 8

    def __init__(self):
        """Init actor"""
        self.threads = []
        self.task_queue = Queue()

        for i in range(self.num_worker_threads):
            t = Thread(target=worker, kwargs={"queue": self.task_queue, "func": self._work})
            t.start()
            self.threads.append(t)

    def _work(self, item):
        """Fetches each binary metadata and publishes metadata to channel"""
        log.debug(item)

    def _clean_up(self):
        for i in range(self.num_worker_threads):
            self.task_queue.put(None)
        for t in self.threads:
            t.join()

    def receiveMessage(self, message, sender):
        """
        Entry Point

        Args:
            message (str): JSON string
            sender (address): The address to send result too

        Expected Format:
            {"sha256": [str, ...], "expiration_seconds": int }

        """
        if isinstance(message, ActorExitRequest):
            self._clean_up()
            return
        elif not isinstance(message, dict) or not isinstance(message.get("sha256", None), list):
            self.send(sender, 'Invalid message format expected: {"sha256": [str, ...], "expiration_seconds": int }')
            return

        # Download binaries from UBS
        found = []
        found.append(message)

        # Iterate through found binaries
        for hash in found:
            self.task_queue.put(hash)

        # Wait until all jobs are completed
        self.task_queue.join()

        self.send(sender, f"Completed: {datetime.now()}")
