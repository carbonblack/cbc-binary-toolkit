import logging

from app import *

from flask import abort, jsonify, request
from schema import SchemaError

from utils.queues import EngineQueue
from utils.schemas import (
    AnalyzeSchema,
    QueueSchema
)

log = logging.getLogger(__name__)
log.setLevel(level=logging.DEBUG)


@app.errorhandler(404)
def object_not_found(e):
    return {"success": False, "message": "Object not found"}, 404


@app.route("/engines", methods=["POST", "DELETE"])
def engine_queue():
    req = request.get_json(force=True)
    log.debug(f"/engines: {req!r}")

    try:
        req = QueueSchema.validate(req)
    except SchemaError as e:
        abort(400, str(e))

    key = req.get("key")

    if request.method == "POST":
        if new_engine(key):
            return jsonify(success=True)

    elif request.method == "DELETE":
        if delete_engine(key):
            return jsonify(success=True), 204


def new_engine(key):
    try:
        if app.config["engine_queues"].get(key) is None:
            # Perist key in database
            database.sadd(ENGINE_QUEUE_KEYS, key)
        app.config["engine_queues"][key] = EngineQueue(key, database)
    except Exception as e:
        log.error("new_engine: Error creating engine queue {}".format(e))
        abort(500)
    return True


def delete_engine(key):
    try:
        if key in app.config["engine_queues"]:
            del app.config["engine_queues"][key]

            # Clear queue from database
            database.srem(ENGINE_QUEUE_KEYS, key)
            return True
    except Exception as e:
        log.error("delete_engine: Error deleting engine queue {}".format(e))
        abort(500)
    abort(404)


@app.route("/analyze", methods=["POST"])
def analyze():
    req = request.get_json(force=True)
    log.debug(f"/analyze: {req!r}")

    try:
        req = AnalyzeSchema.validate(req)
    except SchemaError as e:
        abort(400, str(e))

    if len(app.config["engine_queues"].keys()) == 0:
        return {"success": False, "message": "No queues have been configured"}, 424

    if "hashes" in req:
        hashes = req.get("hashes")
        log.debug("Analyze: {} hash(s)".format(len(hashes)))
        process_hashes(hashes)
    else:
        query = req.get("query")
        log.debug("Analyze: query '{}'}".format(query))
        # TODO: Determine best method for processing query
        #           Long processing time for a large amount of processes what limits to impose?
        # processes = cbth().select(threathunter.Process).where(query)

    return jsonify(success=True)


def process_hashes(hashes):
    if not isinstance(hashes, list) or len(hashes) < 1:
        abort(400)

    try:
        log.debug("Fetching binary metadata information")
        downloads = cbth.select(threathunter.Downloads, hashes)

        for download in downloads.found:
            binary_meta_data = download._info
            th_binary = cbth.select(threathunter.Binary, download.sha256)
            if isinstance(th_binary, threathunter.Binary):
                binary_meta_data.update(th_binary._info)

            for key in app.config["engine_queues"]:
                app.config["engine_queues"][key].enqueue(binary_meta_data)

    except Exception as e:  # noqa
        log.error(f"CbTH responded with an error: {e}")
        abort(500)
