# -*- coding: utf-8 -*-

"""Base for report actor"""

import time
import logging

from thespian.actors import Actor
from schemas import IOCV2Schema
from schema import SchemaError
from cbapi.psc.threathunter import Report, IOC_V2

log = logging.getLogger(__name__)


class ReportActor(Actor):
    """ReportActor"""
    def __init__(self, cbth, engine):
        """Report Actor Constructor"""
        self.cbth = cbth
        self.engine = engine
        self.iocs = []

    def send_report(self, feed_id):
        """Sends IOCs in report to feed"""
        report_meta = {
            "id": "",
            "timestamp": int(time.time()),
            "title": "",
            "description": "",
            "severity": 1,  # TODO: How do you handle intel of varying severity for the run
            "iocs_v2": self.iocs
        }

        report = Report(self.cbth, initial_data=report_meta, feed_id=feed_id)

        report.update()

    def receiveMessage(self, message, sender):
        """Entry Point"""
        try:
            ioc = IOC_V2(self.cbth, initial_data=IOCV2Schema.validate(message))
            self.iocs.append(ioc)

            self.send(sender, True)
        except SchemaError as e:
            log.error(f"IOC format invalid: {e}")
            self.send(sender, False)
