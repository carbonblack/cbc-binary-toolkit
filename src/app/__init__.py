import logging
import redis

import cbapi.psc.threathunter as threathunter
from flask import Flask

from utils.queues import EngineQueue
from utils.schemas import (
    AnalyzeSchema,
    QueueSchema
)

log = logging.getLogger(__name__)
log.setLevel(level=logging.DEBUG)

ENGINE_QUEUE_KEYS = "engine_keys"

app = Flask(__name__)
app.config["engine_queues"] = dict()

cbth = threathunter.CbThreatHunterAPI(profile="sony-custom")
database = redis.Redis.from_url("redis://127.0.0.1:6379")
# Ping database for confirm connection
database.ping()

# Load any engine queue keys on restart
keys = database.smembers(ENGINE_QUEUE_KEYS)
for key in keys:
    key = key.decode("utf-8")
    app.config["engine_queues"][key] = EngineQueue(key, database)


from .routes import *
