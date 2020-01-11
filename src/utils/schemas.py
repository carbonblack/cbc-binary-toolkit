from schema import And, Optional, Or, Schema

AnalyzeSchema = Schema(
    Or(
        {"hashes": And([str], len)},
        {"query": And(str, len), Optional("limit"): And(int, lambda n: n > 0)},
    )
)

QueueSchema = Schema(
    {"key": And(str, len)}
)
