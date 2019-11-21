import logging
import redis

import cbapi.psc.threathunter as threathunter
from flask import Flask, abort, jsonify, request
from queues import EngineQueue
from schema import SchemaError
from schemas import (
    AnalyzeSchema,
    QueueSchema
)

log = logging.getLogger()
log.setLevel(level=logging.DEBUG)

app = Flask(__name__)

cbth = threathunter.CbThreatHunterAPI(profile="sony-custom")
database = redis.Redis.from_url("redis://127.0.0.1:6379")
engine_queues = {}

ENGINE_QUEUE_KEYS = "engine_keys"

@app.route("/queues", methods=["POST", "DELETE"])
def engine_queue():
    req = request.get_json(force=True)
    log.debug(f"/queue: {req!r}")

    try:
        req = QueueSchema.validate(req)
    except SchemaError as e:
        abort(400, str(e))

    key = req.get("key")

    if request.method == "POST":
        if engine_queues.get(key) == None:
            # Perist key in database
            database.sadd(ENGINE_QUEUE_KEYS, key)
            print(key)
        engine_queues[key] = EngineQueue(key, database)
        return jsonify(success=True)

    elif request.method == "DELETE":
        if key in engine_queues:
            del engine_queues[key]

            # Clear queue from database
            database.srem(ENGINE_QUEUE_KEYS, key)
            return jsonify(success=True), 204
        abort(404)

@app.route("/analyze", methods=["POST"])
def analyze():
    req = request.get_json(force=True)
    log.debug(f"/analyze: {req!r}")

    try:
        req = AnalyzeSchema.validate(req)
    except SchemaError as e:
        abort(400, str(e))

    if len(engine_queues.keys()) == 0:
        return { "message": "No queues have been configured" }, 424

    if "hashes" in req:
        hashes = req.get("hashes")
        process_hashes(hashes)
    else:
        log.debug("query")
        # TODO: Determine best method for processing query
        #           Long processing time for a large amount of processes what limits to impose?
        #processes = cbth().select(threathunter.Process).where(query)

    return jsonify(success=True)

def process_hashes(hashes):
    if not isinstance(hashes, list) or len(hashes) < 1:
        abort(400)

    try:
        log.debug("Fetching binary metadata information")
        downloads = cbth.select(threathunter.Downloads, hashes)

        for download in downloads.found:
            binary = download._info
            binary_meta = cbth.select(threathunter.Binary, download.sha256)
            if isinstance(binary_meta, threathunter.Binary):
                binary.update(binary_meta._info)

            for key in engine_queues:
                engine_queues[key].enqueue(binary)

    except Exception as e:  # noqa
        log.error(f"CbTH responded with an error: {e}")
        abort(500)

def main():
    # Ping database for confirm connection
    database.ping()

    # Load any engine queue keys on restart
    keys = database.smembers(ENGINE_QUEUE_KEYS)
    for key in keys:
        key = key.decode("utf-8")
        engine_queues[key] = EngineQueue(key, database)

    app.run(host="127.0.0.1", port="5000", debug=True)


if __name__ == "__main__":
    main()
