import logging
import redis
import sys

import cbapi.psc.threathunter as threathunter
from flask import Flask

from utils.queues import EngineQueue

log = logging.getLogger(__name__)
log.setLevel(level=logging.DEBUG)

ENGINE_QUEUE_KEYS = "engine_keys"

app = Flask(__name__)
app.config["engine_queues"] = dict()

if 'pytest' in sys.modules:
    cbth = threathunter.CbThreatHunterAPI(profile="sony-custom")
    database = redis.Redis.from_url("redis://127.0.0.1:6379")
    # Ping database for confirm connection
    database.ping()

    # Load any engine queue keys on restart
    keys = database.smembers(ENGINE_QUEUE_KEYS)
    for key in keys:
        key = key.decode("utf-8")
        app.config["engine_queues"][key] = EngineQueue(key, database)
else:
    cbth = threathunter.CbThreatHunterAPI(url="https://example.com", token="ABCD/1234", org_key="Z100", ssl_verify=True)
    database = None


from .routes import *
