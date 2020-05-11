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

"""Schemas for Engine Results component"""

from schema import And, Or, Optional, Schema

IOCv2SEVSchema = Schema(
    {
        "id": And(str, len),
        "match_type": And(str, lambda type: type in ["query", "equality", "regex"]),
        "values": And([str], len),
        Optional("field"): And(str, len),
        Optional("link"): And(str, len),
        "severity": And(int, lambda n: n > 0 and n < 11)  # Needs stripped before sent to CBC
    }
)

IOCv2Schema = Schema(
    {
        "id": And(str, len),
        "match_type": And(str, lambda type: type in ["query", "equality", "regex"]),
        "values": And([str], len),
        Optional("field"): And(str, len),
        Optional("link"): And(str, len)
    }
)

ReportSchema = Schema(
    {
        "id": And(str, len),
        "timestamp": And(int, lambda n: n > 0),
        "title": And(str, len),
        "description": And(str, len),
        "severity": And(int, lambda n: n > 0 and n < 11),
        Optional("link"): str,
        Optional("tags"): [str],
        "iocs_v2": [IOCv2Schema],
        Optional("visibility"): str
    }
)

EngineResponseSchema = Schema(
    {
        "iocs": [IOCv2SEVSchema],
        "engine_name": And(str, len),
        "binary_hash": And(str, lambda n: len(n) == 64),
        "success": bool
    }
)

BinaryMetadataSchema = Schema(
    {
        "sha256": And(str, lambda n: len(n) == 64),
        "url": And(str, len),
        "architecture": [str],
        "available_file_size": Or(int, None),
        "charset_id": Or(int, None),
        "comments": Or(str, None),
        "company_name": Or(str, None),
        "copyright": Or(str, None),
        "file_available": bool,
        "file_description": Or(str, None),
        "file_size": Or(int, None),
        "file_version": Or(str, None),
        "internal_name": Or(str, None),
        "lang_id": Or(int, None),
        "md5": And(str, lambda n: len(n) == 32),
        "original_filename": Or(str, None),
        "os_type": Or(str, None),
        "private_build": Or(str, None),
        "product_description": Or(str, None),
        "product_name": Or(str, None),
        "product_version": Or(str, None),
        "special_build": Or(str, None),
        "trademark": Or(str, None)
    }
)
