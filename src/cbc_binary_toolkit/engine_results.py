# -*- coding: utf-8 -*-

"""Base for engine response validation, acceptance, and state checkpointing"""


import logging
import time
import uuid

from schema import SchemaError
from .schemas import EngineResponseSchema, IOCV2Schema
from cbapi.psc.threathunter import Report

log = logging.getLogger(__name__)

SEVERITY_RANGE = 10


class EngineResults:
    """
    Engine Results Handler

    Require Properties:
        engine_name (str): The name of the engine analysis is coming from
        state_manager (cbc_binary_toolkit.state.manager): State management component
        cbth (CbThreatHunterAPI): CBAPI ThreatHunter API to push reports to Carbon Black Cloud

    Description:
        Validates an EngineResponse
        Validates and manages IOCs (Threat Inteligence) from the Analysis Engines
        Updates state checkpoint to 'DONE' for an EngineResponse
        Adds IOCs from an EngineResponse to stored list
        Sends reports with IOCs to Carbon Black Cloud

    Note:
        IOCs are grouped by severity to increase performance on Carbon Black Cloud
    """

    def __init__(self, engine_name, state_manager, cbth):
        """Engine Results Handler Constructor"""
        self.engine_name = engine_name
        self.state_manager = state_manager
        self.cbth = cbth
        # Create range of report levels
        self.iocs = list(list() for i in range(SEVERITY_RANGE))

    def _validate_response(self, engine_response):
        """
        Validate the analysis response from engine against EngineResponseSchema

        Args:
            engine_response (EngineResponseSchema): Analysis from engine

        Returns:
            bool: True if engine_response adheres to EngineResponseSchema,
                    False otherwise
        """
        try:
            if engine_response["success"]:
                EngineResponseSchema.validate(engine_response)
                return True
            else:
                log.error(f"Analysis Engine {engine_response['engine_name']} failed during analysis"
                          f" of hash {engine_response['binary_hash']}")
                return False
        except (SchemaError, KeyError, TypeError) as e:
            log.error(f"Analysis engine reponse does not conform to EngineResponseSchema: {e}")
            raise
            return False

    def _store_ioc(self, ioc):
        """
        Store IOC in internal list

        Args:
            ioc (JSON): IOC to add to internal list

        Returns:
            bool: True if IOC was added to internal list successfully,
                    False otherwise
        """
        try:
            ioc_valid = IOCV2Schema.validate(ioc)
            severity = ioc.get("severity", None)
            if (severity is not None and isinstance(severity, int) and severity > 0 and severity <= SEVERITY_RANGE):
                del ioc_valid["severity"]
                self.iocs[severity - 1].append(ioc_valid)
                return True
            log.error("Severity not provide with IOC")
        except SchemaError as e:
            log.error(f"IOC format invalid: {e}")
        return False

    def _accept_report(self, engine_name, iocs):
        """
        Add Report IOCs returned from Analysis Engine to report_item list

        Args:
            engine_name (str): Name of the engine that performed analysis
            iocs (list): IOCs to add to the state manager

        Returns:
            bool: True if the IOCs were added to the state manager,
                    False otherwise
        """
        try:
            for ioc in iocs:
                IOCV2Schema.validate(ioc)
                self.state_manager.add_report_item(ioc["severity"], engine_name, ioc)
                self._store_ioc(ioc)
            return True
        except SchemaError as e:
            log.error(f"Error caught when trying to add a report item (IOC record) to stored list: {e}")
            raise
            return False

    def _update_state(self, binary_hash, engine_name):
        """
        Update the checkpoint of binary_hash in state_manager to 'DONE'

        Args:
            binary_hash (str): Hash to update checkpoint for
            engine_name (str): Name of engine that performed analysis

        Returns:
            bool: True if the checkpoint for binary_hash was updated successfully,
                    False otherwise
        """
        try:
            self.state_manager.set_checkpoint(binary_hash, engine_name, "DONE")
            return True
        except Exception as e:
            log.error(f"Error caught when trying to update the state manager checkpoint for Engine Results: {e}")
            raise
            return False

    def receive_response(self, engine_response):
        """
        Use private functions to validate engine response, update state, store IOCs

        Args:
            engine_response (EngineResponseSchema): Analysis from engine

        Returns:
            bool: True if engine_response was validated, accepted, and had state updated,
                    False otherwise
        """
        if self._validate_response(engine_response):
            report_accepted = self._accept_report(engine_response["engine_name"], engine_response["iocs"])
            state_updated = self._update_state(engine_response["binary_hash"], engine_response["engine_name"])
            if state_updated and report_accepted:
                return True
        else:
            log.error("Validation of Analysis Engine Response failed.")
        return False

    def _send_reports(self, feed_id):
        """
        Send IOCs in stored list to feed

        Args:
            feed_id (str): The id of the feed that the report will be published too

        Returns:
            bool: True if at least one report was sent to feed_id,
                    False otherwise
        """
        try:
            some_reports_sent = False
            for sev in range(SEVERITY_RANGE):
                if len(self.iocs[sev]) > 0:
                    now = time.time()
                    report_meta = {
                        "id": str(uuid.uuid4()),
                        "timestamp": int(now),
                        "title": f"{self.engine_name} Severity {sev + 1} - "
                                 f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now))}",
                        "description": "Automated report generated by Binary Analysis SDK",
                        "severity": sev + 1,
                        "iocs_v2": self.iocs[sev]
                    }

                    report = Report(self.cbth, initial_data=report_meta, feed_id=feed_id)
                    report.update()
                    log.info(f"Report ({report_meta['title']}) sent to feed {feed_id}")
                    some_reports_sent = True
                    # Clear report items from the database
                    self.state_manager.clear_report_items(sev + 1, self.engine_name)
            return some_reports_sent
        except Exception as e:
            log.error(f"Error while sending reports to feed {feed_id}: {e}")
            return False

    def send_reports(self, feed_id):
        """
        Initiate sending reports to feed

        Args:
            feed_id (str): Feed to send reports to

        Returns:
            reports_sent (bool): True if all reports from interal list were sent successfully,
                                    False otherwise
        """
        reports_sent = False
        if isinstance(feed_id, str):
            log.info(f"Sending reports to feed: {feed_id}")
            reports_sent = self._send_reports(feed_id)
        return reports_sent
