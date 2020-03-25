# -*- coding: utf-8 -*-

"""Base for engine response validation, acceptance, and state checkpointing"""


import logging
from schema import SchemaError
from .schemas import EngineResponseSchema, IOCV2Schema
log = logging.getLogger(__name__)


class EngineResults:
    """Validate an EngineResponse, update state checkpoint to 'DONE', and add IOCs to stored list"""

    def __init__(self, state_manager):
        """Validation of Engine Responses"""
        self.state_manager = state_manager

    def _update_state(self, binary_hash, engine_name):
        """Update the checkpoint of binary_hash in state_manager to 'DONE'"""
        try:
            self.state_manager.set_checkpoint(binary_hash, engine_name, "DONE")
            return True
        except Exception as e:
            log.error(f"Error caught when trying to update the state manager checkpoint for Engine Results: {e}")
            raise
            return False

    def _accept_report(self, engine_name, iocs):
        """Add Report IOCs returned from Analysis Engine to report_item list, and increase count of reports received"""
        try:
            for ioc in iocs:
                IOCV2Schema.validate(ioc)
                self.state_manager.add_report_item(ioc["severity"], engine_name, ioc)
            return True
        except SchemaError as e:
            log.error(f"Error caught when trying to add a report item (IOC record) to stored list: {e}")
            raise
            return False

    def _validate_response(self, engine_response):
        """Validate the analysis response from engine against EngineResponseSchema"""
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

    def receive_response(self, engine_response):
        """Use private functions to validate engine response, update state, store IOCs"""
        if self._validate_response(engine_response):
            state_updated = self._update_state(engine_response["binary_hash"], engine_response["engine_name"])
            report_accepted = self._accept_report(engine_response["engine_name"], engine_response["iocs"])
            if state_updated and report_accepted:
                return True
        else:
            log.error("Validation of Analysis Engine Response failed.")
        return False
