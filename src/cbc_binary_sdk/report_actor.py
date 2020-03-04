# -*- coding: utf-8 -*-

"""Base for report actor"""

import time
import logging
import uuid

from thespian.actors import ActorTypeDispatcher
from thespian.initmsgs import initializing_messages
from schema import SchemaError
from cbapi.psc.threathunter import CbThreatHunterAPI, Report
from .schemas import IOCV2Schema
from cbc_binary_sdk import InitializationError

log = logging.getLogger(__name__)

SEVERITY_RANGE = 10


@initializing_messages([("cbth", CbThreatHunterAPI), ("engine_name", str)], initdone='_verify_init')
class ReportActor(ActorTypeDispatcher):
    """
    ReportActor

    Require Properties:
        cbth (CbThreatHunterAPI): CBAPI ThreatHunter API to push reports to Carbon Black Cloud
        engine_name (str): The name of the engine that the report actor is attached too

    Description:
        Validates and manages IOCs (Threat Inteligence) from the Analysis Engines
        Supports command(s) to send reports to Carbon Black Cloud

    Note:
        IOCs are grouped by severity to increase performance on Carbon Black Cloud

    """
    def __init__(self):
        """
        Report Actor Constructor

        Description:
            Manages and consolidates IOCs into reports of common severity
            Pushes reports when indicated by send_reports(feed_id: str)

        """
        # Create range of report levels
        self.iocs = list(list() for i in range(SEVERITY_RANGE))

    def _verify_init(self):
        """Verifies that the actor has the necessary properties to initialize"""
        if not isinstance(self.cbth, CbThreatHunterAPI) or \
           not isinstance(self.engine_name, str):
            raise InitializationError

    def _send_reports(self, feed_id):
        """
        Sends IOCs in report to feed

        Args:
            feed_id (str): The id of the feed that the report will be published too

        Returns:
            bool: Indicates if reports successfully sent

        """
        try:
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

                    log.info(f"Sending report to feed {feed_id}: {report_meta['title']}")
                    report = Report(self.cbth, initial_data=report_meta, feed_id=feed_id)
                    report.update()
            return True
        except Exception as e:
            log.error(f"Error while sending reports to feed {feed_id}: {e}")
            return False

    def receiveMsg_ActorExitRequest(self, message, sender):
        """
        Clean up handler

        Args:
            message (ActorExitRequest): thespian.actors.ActorExitRequest that terminates actor
            sender (address): The address to send result too

        """
        return

    def receiveUnrecognizedMessage(self, message, sender):
        """
        Unrecognized message handler

        Args:
            message (?): Any message type not explicitly handled
            sender (address): The address to send result too

        """
        log.error(f"Unrecognized message type: {type(message)}")
        self.send(sender, False)

    def receiveMsg_tuple(self, message, sender):
        """
        Command handler

        Args:
            message (tuple): ( command , ... )
            sender (address): The address to send result too

        Commands:
            Send Report: ( "SEND_REPORTS", "feed_id (str)" )

        """
        if message[0] == "SEND_REPORTS" and isinstance(message[1], str):
            log.info(f"Sending reports to feed: {message[1]}")
            self.send(sender, self._send_reports(message[1]))
        else:
            log.error(f"Unsupported command: {message[0]}")
            self.send(sender, False)

    def receiveMsg_dict(self, message, sender):
        """
        IOC handler

        Args:
            message (str): JSON string
            sender (address): The address to send result too

        Expected Format:
            {
                "id": And(str, len),
                "match_type": And(str, lambda type: type in ["query", "equality", "regex"]),
                "values": And([str], len),
                 Optional("field"): And(str, len),
                 Optional("link"): And(str, len),
                "severity": int(1 - 10),
            }

        """
        try:
            ioc_valid = IOCV2Schema.validate(message)

            severity = message.get("severity", None)
            if severity is not None and isinstance(severity, int) and severity > 0 and severity <= SEVERITY_RANGE:
                self.iocs[severity - 1].append(ioc_valid)
                return self.send(sender, True)

            log.error("Severity not provide with IOC")
        except SchemaError as e:
            log.error(f"IOC format invalid: {e}")
        self.send(sender, False)
