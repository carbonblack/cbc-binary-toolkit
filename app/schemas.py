import validators
import dateutil.parser
from croniter import croniter
from schema import And, Optional, Or, Schema, Use

AnalyzeSchema = Schema(
    Or(
        {"hashes": And([str], len)},
        {"query": And(str, len), Optional("limit"): And(int, lambda n: n > 0)},
    )
)

QueueSchema = Schema(
    { "key": And(str, len) }
)
