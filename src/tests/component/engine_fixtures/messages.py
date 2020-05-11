# -*- coding: utf-8 -*-

# *******************************************************
# Copyright (c) VMware, Inc. 2019. All Rights Reserved.
# SPDX-License-Identifier: MIT
# *******************************************************
# *
# * DISCLAIMER. THIS PROGRAM IS PROVIDED TO YOU "AS IS" WITHOUT
# * WARRANTIES OR CONDITIONS OF ANY KIND, WHETHER ORAL OR WRITTEN,
# * EXPRESS OR IMPLIED. THE AUTHOR SPECIFICALLY DISCLAIMS ANY IMPLIED
# * WARRANTIES OR CONDITIONS OF MERCHANTABILITY, SATISFACTORY QUALITY,
# * NON-INFRINGEMENT AND FITNESS FOR A PARTICULAR PURPOSE.

"""Engine fixtures for testing"""

IOCS_1 = [{
          "id": "j39sbv7",
          "match_type": "equality",
          "values": ["127.0.0.1"],
          "severity": 1,
          },
          {
          "id": "kfsd982m",
          "match_type": "equality",
          "values": ["127.0.0.2"],
          "severity": 1,
          },
          {
          "id": "slkf038",
          "match_type": "equality",
          "values": ["app.exe"],
          "severity": 10,
          },
          {
          "id": "0kdl4uf9",
          "match_type": "regex",
          "values": [".*google.*"],
          "severity": 3,
          }]

IOCS_2 = [{
          "id": "s9dlk2m1",
          "match_type": "query",
          "values": ["netconn_ipv4:127.0.0.1"],
          "severity": 2,
          }]

IOCS_3 = [{
          "id": "jsoq301n",
          "match_type": "equality",
          "values": ["127.0.0.1"],
          "severity": 1,
          },
          {
          "id": "ci2js01l",
          "match_type": "equality",
          "values": ["127.0.0.2"],
          "severity": 1,
          },
          {
          "id": "d83nsmc4",
          "match_type": "equality",
          "values": ["app.exe"],
          "severity": 10,
          },
          {
          "id": "cj01nsbds",
          "match_type": "equality",
          "values": ["127.0.0.3"],
          "severity": 1,
          },
          {
          "id": "feh48sk1",
          "match_type": "equality",
          "values": ["127.0.0.4"],
          "severity": 1,
          },
          {
          "id": "d02kfn63",
          "match_type": "equality",
          "values": ["bad.exe"],
          "severity": 10,
          },
          {
          "id": "cje828jc",
          "match_type": "regex",
          "values": [".*google.*"],
          "severity": 3,
          },
          {
          "id": "s9dlk2m1",
          "match_type": "query",
          "values": ["netconn_ipv4:127.0.0.1"],
          "severity": 2,
          }]

IOC_HASH = [{
    "id": "j39sbv7",
    "match_type": "equality",
    "values": ["405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4"],
    "severity": 1,
}]

IOCS_INVALID = [{
                "id": "s9dlk2m1",
                "match_type": "query",
                "values": ["netconn_ipv4:127.0.0.1"],
                "severity": -10,
                }]


UNFINISHED_STATE = {
    "file_size": 2000000,
    "file_name": "blort.exe",
    "os_type": "WINDOWS",
    "engine_name": "!!REPLACE!!",
    "time_sent": "2020-01-15T12:00:00"
}

FINISHED_STATE = {
    "file_size": 2000000,
    "file_name": "foobar.exe",
    "os_type": "WINDOWS",
    "engine_name": "!!REPLACE!!",
    "time_sent": "2020-01-14T12:00:00",
    "time_returned": "2020-01-14T12:05:00"
}

MESSAGE_VALID = {
    "iocs": IOCS_1,
    "engine_name": "TEST_ENGINE",
    "binary_hash": "0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc",
    "success": True
}

MESSAGE_VALID_1 = {
    "iocs": IOCS_2,
    "engine_name": "TEST_ENGINE",
    "binary_hash": "0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc",
    "success": True
}

MESSAGE_VALID_2 = {
    "iocs": IOCS_3,
    "engine_name": "TEST_ENGINE",
    "binary_hash": "0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc",
    "success": True
}

ENGINE_FAILURE = {
    "iocs": [],
    "engine_name": "TEST_ENGINE",
    "binary_hash": "0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc",
    "success": False
}

MESSAGE_INVALID = {
    "INVALID": "Bad schema",
    "binary_hash": "0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc"
}
