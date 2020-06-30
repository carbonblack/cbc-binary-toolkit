# -*- coding: utf-8 -*-

# *******************************************************
# Copyright (c) VMware, Inc. 2020. All Rights Reserved.
# SPDX-License-Identifier: MIT
# *******************************************************
# *
# * DISCLAIMER. THIS PROGRAM IS PROVIDED TO YOU "AS IS" WITHOUT
# * WARRANTIES OR CONDITIONS OF ANY KIND, WHETHER ORAL OR WRITTEN,
# * EXPRESS OR IMPLIED. THE AUTHOR SPECIFICALLY DISCLAIMS ANY IMPLIED
# * WARRANTIES OR CONDITIONS OF MERCHANTABILITY, SATISFACTORY QUALITY,
# * NON-INFRINGEMENT AND FITNESS FOR A PARTICULAR PURPOSE.

"""Test code for the persistence state manager."""

import copy

from datetime import datetime
from dateutil.parser import parse
from cbc_binary_toolkit.state.manager import BasePersistor, BasePersistorFactory

SEVERITY_RANGE = 10


class MockPersistor(BasePersistor):
    """Mock Persistor"""

    def __init__(self):
        """Constructor"""
        self.db = dict()
        self.iocs = list(dict() for i in range(SEVERITY_RANGE))

    def get_file_state(self, binary_hash, engine=None):
        """Mock get file state"""
        return self.db.get(binary_hash, None)

    def set_checkpoint(self, binary_hash, engine_name, checkpoint_name, checkpoint_time=None):
        """Mock set_checkpoint"""
        self.db[binary_hash] = dict()
        self.db[binary_hash]["engine_name"] = engine_name
        self.db[binary_hash]["checkpoint_name"] = checkpoint_name

        if not checkpoint_time:
            checkpoint_time = datetime.now()
        self.db[binary_hash]["checkpoint_time"] = checkpoint_time
        self.db[binary_hash]["file_hash"] = binary_hash

    def get_previous_hashes(self, engine_name):
        """Mock get_previous_hashes"""
        return list(self.db.keys())

    def get_unfinished_hashes(self, engine):
        """Mock get_unfinished_states"""
        unfinished = []
        for key in self.db.keys():
            if self.db[key]["engine_name"] == engine and self.db[key].get("checkpoint_name", None) != "DONE":
                unfinished.append((key, self.db[key].get("checkpoint_name", None)))
        return unfinished

    def prune(self, timestamp):
        """Mock prune"""
        prune_time = parse(timestamp)
        for key in self.db.keys():
            if parse(self.db[key]["checkpoint_time"]) < prune_time:
                del self.db[key]

    def add_report_item(self, severity, engine_name, data):
        """Mock add_report_item"""
        report_group = self.iocs[severity - 1]

        if engine_name not in report_group:
            report_group[engine_name] = []

        report_group[engine_name].append(copy.deepcopy(data))


class MockPersistorFactory(BasePersistorFactory):
    """Mock Persistor Factory"""
    def create_persistor(self, config):
        """Mock create persistor"""
        return MockPersistor()
