import redis
import logging
import json

log = logging.getLogger(__name__)
log.setLevel(level=logging.DEBUG)

class EngineQueue:

    def __init__(self, key, connection):
        self.key = key
        self.db = connection


    def enqueue(self, binary_meta_data):
        if isinstance(binary_meta_data, dict):
            self.db.rpush(self.key, json.dumps(binary_meta_data))
            log.debug('Binary {} added to queue {}'.format(binary_meta_data["sha256"], self.key))
        else:
            raise TypeError('EngineQueue method enqueue only accepts type dict')
