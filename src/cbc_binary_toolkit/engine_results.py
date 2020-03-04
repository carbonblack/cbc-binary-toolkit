# -*- coding: utf-8 -*-

"""Base for engine results acceptance and processing"""


import logging
import time
import traceback
from datetime import datetime
from threading import Thread, Event
from thespian.actors import ActorAddress, ActorSystem

from schema import SchemaError
from .schemas import EngineResponseSchema
from cbc_binary_toolkit.state import StateManager
from cbc_binary_toolkit.pubsub import PubSubManager
from cbc_binary_toolkit.config import Config
from cbc_binary_toolkit import InitializationError
log = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SEC = 300


class EngineResultsThread(Thread):
    """Pull from pub/sub results queue, update state management, give to results actor"""

    def __init__(self, group=None, target=None, name=None,
                 args=(), kwargs=None, verbose=None):
        """Engine Results processing thread, pulling from results pub/sub queue"""
        super(EngineResultsThread, self).__init__(group=group, target=target, name=name)
        self.kwargs = kwargs
        self._verify_init()
        self.report_actor = kwargs.get("report_actor", None)
        self.state_manager = kwargs.get("state_manager", None)
        self.config = kwargs.get("config", None)
        self.pub_sub_manager = kwargs.get("pub_sub_manager", None)
        self.timeout = kwargs.get("timeout", DEFAULT_TIMEOUT_SEC)

        self.result_queue_name = self.config.string("pubsub.result_queue_name")

        self.received_binary_counts = {}
        self.last_time_results_received = datetime.now()
        self.timeout_check = Event()
        self.completion_check = Event()
        self.timeout_thread = Thread(target=self._check_timeout)
        return

    def _verify_init(self):
        if not self.kwargs or \
           not isinstance(self.kwargs.get("state_manager", None), StateManager) or \
           not isinstance(self.kwargs.get("pub_sub_manager", None), PubSubManager) or \
           not isinstance(self.kwargs.get("config", None), Config) or \
           not isinstance(self.kwargs.get("report_actor", None), ActorAddress) or \
           not isinstance(self.kwargs.get("timeout", DEFAULT_TIMEOUT_SEC), int):
            raise InitializationError

    def _check_timeout(self):
        while True:
            now = datetime.now()
            if self.completion_check.is_set():
                break
            elif (now - self.last_time_results_received).seconds > self.timeout:
                log.warning(f"Haven't received results from an analysis engine in "
                            f"{(now - self.last_time_results_received).seconds}"
                            f" seconds. Ending EngineResultsThread.")
                self.timeout_check.set()
                self.pub_sub_manager.put(self.result_queue_name, None)
                return True
            else:
                time.sleep(1)

    def run(self):
        """Autorun function on thread start"""
        try:
            self.timeout_thread.start()
            while not self.timeout_check.is_set():
                work_item = self.pub_sub_manager.get(self.result_queue_name)
                if self._work(work_item):
                    break
        except Exception as e:
            log.error(f"Error caught in worker: {e}\n {traceback.format_exc()}")
        # self.join()

    def _work(self, work_item):
        """
        Process result from result queue

        Checks timeout and EningeResponseSchema, updates the state manager, passes IOC
        to report actor, and signals if completed.

        """
        if not work_item:
            # we've timed out
            return
        else:
            try:
                self.last_time_results_received = datetime.now()  # reset timeout time check variable
                engine_response_valid = EngineResponseSchema.validate(work_item)
                iocs = engine_response_valid.get("iocs", None)
                engine_name = engine_response_valid.get("engine_name", None)
                binary_hash = engine_response_valid.get("binary_hash", None)

                self._update_state(binary_hash, engine_name)
                self._accept_report(engine_name, iocs)
                completed_engine_analysis = self._check_completion(engine_name)

                if completed_engine_analysis:
                    log.debug(f"{engine_name} has completed analysis of {self.received_binary_counts[engine_name]}"
                              f" reports.")
                    resp = ActorSystem().ask(self.report_actor,
                                             ("SEND_REPORTS", self.config.string("engine.feed_id")),
                                             10)
                    log.debug(f"EngineResultsThread asking {self.report_actor} to SEND_REPORTS: {resp}")

                    # Kill timeout thread
                    self.completion_check.set()
                    return True
                else:
                    log.debug("Haven't finished engine")
            except SchemaError as e:
                log.error(f"Message to Engine Results Actor does not conform to EngineResponseSchema: {e}")
            return False

    def _update_state(self, binary_hash, engine_name):
        """Update the state of binary_hash in state_manager to record time_returned"""
        try:
            info_dict = {}
            info_dict["time_returned"] = datetime.now()
            state_manager = self.state_manager
            file_info = state_manager.lookup(binary_hash, engine_name)
            persist_id = file_info["persist_id"]

            state_manager.set_file_state(binary_hash, info_dict, persist_id)
        except Exception as e:
            log.error(f"Error caught when trying to update the state manager: {e}")

    def _accept_report(self, engine_name, iocs):
        """Add Report IOCs returned from Analysis Engine to report_item list, and increase count of reports received"""
        try:
            state_manager = self.state_manager
            for ioc in iocs:
                state_manager.add_report_item(ioc["severity"], engine_name, ioc)
                resp = ActorSystem().ask(self.report_actor, ioc, 10)
                log.debug(f"Response asking {self.report_actor} an IOC: {resp}")
            if engine_name in self.received_binary_counts:
                self.received_binary_counts[engine_name] += 1
            else:
                self.received_binary_counts[engine_name] = 1
        except Exception as e:
            log.error(f"Error caught when trying to give IOC to report actor: {e}")

    def _check_completion(self, engine_name):
        """Check for equality between num reports given to analysis engine and num reports received from that engine."""
        state_manager = self.state_manager

        unfinished_states = state_manager.get_num_unfinished_states()

        if engine_name not in unfinished_states:
            log.error(f"Received report for engine {engine_name}, but this engine hasn't been sent reports to analyze.")
        else:
            # Assumes ingestion will process hashes faster than analysis engines return IOCs
            if unfinished_states[engine_name] == 0:
                return True
        return False
