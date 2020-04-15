# -*- coding: utf-8 -*-

"""Schemas for Engine Results component"""

from schema import And, Or, Optional, Schema

IOCV2Schema = Schema(
    {
        "id": And(str, len),
        "match_type": And(str, lambda type: type in ["query", "equality", "regex"]),
        "values": And([str], len),
        Optional("field"): And(str, len),
        Optional("link"): And(str, len),
        "severity": And(int, lambda n: n > 0 and n < 11)  # Needs stripped before sent to CBC
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
        # "iocs": IOCs,
        # iocs_v2": [IOCV2Schema],
        Optional("visibility"): str
    }
)

EngineResponseSchema = Schema(
    {
        "iocs": [IOCV2Schema],
        "engine_name": And(str, len),
        "binary_hash": And(str, len),
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
        "trademark": Or(str, None),
        "persist_id": int
    }
)
