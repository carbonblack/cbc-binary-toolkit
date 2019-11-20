import redis
import logging
import json

log = logging.getLogger(__name__)
log.setLevel(level=logging.DEBUG)

class EngineQueue:

    def __init__(self, key, connection):
        self.key = key
        self.db = connection


    def enqueue(self, binary):
        if isinstance(binary, dict):
            self.db.rpush(self.key, json.dumps(binary))
            log.debug('Binary {} added to queue {}'.format(binary["sha256"], self.key))
        else:
            raise TypeError('Binary must be of type dict')
