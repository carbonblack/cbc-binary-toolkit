# -*- coding: utf-8 -*-

"""Base for ingestion actor"""

import logging
import traceback

from thespian.actors import Actor, ActorExitRequest
from thespian.initmsgs import initializing_messages
from queue import Queue
from threading import Thread
from types import MethodType
from datetime import datetime
from cbapi.psc.threathunter import CbThreatHunterAPI
from cb_binary_analysis import InitializationError
from cb_binary_analysis.state import StateManager
from .ubs import download_hashes, get_metadata
from cb_binary_analysis.config import Config

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


@initializing_messages([
                       ("state_manager", StateManager),
                       ("cbth", CbThreatHunterAPI),
                       ("config", Config)
                       ], initdone='_verify_init')
class IngestionActor(Actor):
    """
    IngestionActor

    Description:
        Manages the fetching of the binary's metadata to send to the analysis engine(s)
        Hashes are only processed if they are not present in the cache

    """

    num_worker_threads = 8
    DEFAULT_EXPIRATION = 3600

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
        log.debug(f"Worker received: {item}")
        try:
            metadata = get_metadata(self.cbth, item)

            # Save hash entry to state manager
            self.state_manager.set_file_state(item["sha256"],
                                              {
                                              "file_size": metadata["file_size"],
                                              "file_name": metadata["original_filename"],
                                              "os_type": metadata["os_type"],
                                              "engine_name": self.config.string("engine.name"),
                                              "time_sent": datetime.now()
                                              })
            # Send to Pub/Sub
        except Exception as e:
            log.error(f"Error caught in worker: {e}\n {traceback.format_exc()}")

    def _clean_up(self):
        for i in range(self.num_worker_threads):
            self.task_queue.put(None)
        for t in self.threads:
            t.join()

    def _verify_init(self):
        if not isinstance(self.cbth, CbThreatHunterAPI) or \
           not isinstance(self.config, Config) or \
           not isinstance(self.state_manager, StateManager):
            raise InitializationError

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

        hashes = message.get("sha256")
        new_hashes = []

        # Check previously seen hashes
        for i in range(0, len(hashes)):
            if self.state_manager.lookup(hashes[i]) is None:
                new_hashes.append(hashes[i])
            else:
                log.info(f"Hash {hashes[i]} has already been analyzed")

        # Download binaries from UBS
        found = download_hashes(self.cbth, new_hashes, message.get("expiration_seconds", self.DEFAULT_EXPIRATION))

        # Iterate through found binaries
        if isinstance(found, list):
            for hash in found:
                self.task_queue.put(hash)

            # Wait until all jobs are completed
            self.task_queue.join()

        self.send(sender, f"Completed: {datetime.now()}")
