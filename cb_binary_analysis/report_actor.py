# -*- coding: utf-8 -*-

"""Base for report actor"""

import time
import logging

from thespian.actors import Actor
from schemas import IOCV2Schema
from schema import SchemaError
from cbapi.psc.threathunter import Report, IOC_V2

log = logging.getLogger(__name__)

SEVERITY_RANGE = 10


class ReportActor(Actor):
    """ReportActor"""
    def __init__(self, cbth, engine):
        """
        Report Actor Constructor

        Description:
            Manages and consolidates IOCs into reports of common severity
            Pushes reports when indicated by send_reports(feed_id: str)

        """
        self.cbth = cbth
        self.engine = engine

        # Create range of report levels
        self.iocs = list()
        for sev in range(SEVERITY_RANGE):
            self.iocs[sev] = list()

    def send_reports(self, feed_id):
        """
        Sends IOCs in report to feed

        Args:
            feed_id (str): The id of the feed that the report will be published too

        """
        for sev in range(SEVERITY_RANGE):
            report_meta = {
                "id": "",
                "timestamp": int(time.time()),
                "title": "",
                "description": "",
                "severity": sev,
                "iocs_v2": self.iocs[sev]
            }

            report = Report(self.cbth, initial_data=report_meta, feed_id=feed_id)
            report.update()

    def receiveMessage(self, message, sender):
        """
        Entry Point

        Args:
            message (str): JSON string
            sender (address): The address to send result too

        Expected Format:
            {
                "severity": int(1 - 10),
                "iocs": [
                    {
                        "id": And(str, len),
                        "match_type": And(str, lambda type: type in ["query", "equality", "regex"]),
                        "values": And([str], len),
                        Optional("field"): And(str, len),
                        Optional("link"): And(str, len)
                    },
                    ...
                ]
            }

        """
        try:
            ioc = IOC_V2(self.cbth, initial_data=IOCV2Schema.validate(message.get("iocs", [])))

            severity = message.get("severity", None)
            if severity is not None and isinstance(severity, int):
                self.iocs[severity].extend(ioc)
                self.send(sender, True)
                return

            log.error("Severity not provide with IOC")
        except SchemaError as e:
            log.error(f"IOC format invalid: {e}")
        self.send(sender, False)
