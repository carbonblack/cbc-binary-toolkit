# -*- coding: utf-8 -*-

"""Schemas for ReportActor"""

from schema import And, Optional, Schema

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
        "iocs": And([IOCV2Schema], len),
        "engine_name": And(str, len),
        "binary_hash": And(str, len),
        "success": bool
    }
)
