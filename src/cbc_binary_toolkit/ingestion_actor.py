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
from .errors import InitializationError
from cbc_binary_toolkit.state import StateManager
from cbc_binary_toolkit.pubsub import PubSubManager
from .ubs import download_hashes, get_metadata
from cbc_binary_toolkit.config import Config

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
                       ("pub_sub_manager", PubSubManager),
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
            engine_name = self.config.string("engine.name")

            # Save hash entry to state manager
            metadata["persist_id"] = self.state_manager.set_file_state(item["sha256"],
                                                                       {
                                                                       "file_size": metadata["file_size"],
                                                                       "file_name": metadata["original_filename"],
                                                                       "os_type": metadata["os_type"],
                                                                       "engine_name": engine_name,
                                                                       "time_sent": datetime.now()
                                                                       })

            # Send to Pub/Sub
            self.pub_sub_manager.put(engine_name, metadata)
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
           not isinstance(self.state_manager, StateManager) or \
           not isinstance(self.pub_sub_manager, PubSubManager):
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
        new_hashes = dict()

        # Check previously seen hashes
        for hash in hashes:
            if self.state_manager.lookup(hash) is None and new_hashes.get(hash, True):
                new_hashes[hash] = False
            else:
                log.info(f"Hash {hash} has already been analyzed")

        # Download binaries from UBS
        found = download_hashes(self.cbth,
                                list(new_hashes.keys()),
                                message.get("expiration_seconds", self.DEFAULT_EXPIRATION))

        # Iterate through found binaries
        if isinstance(found, list):
            for hash in found:
                self.task_queue.put(hash)

            # Wait until all jobs are completed
            self.task_queue.join()

        self.send(sender, f"Injested: {datetime.now()}")
