

import sqlite3


class SQLiteBasedPersistor:
    def __init__(self, conn):
        self._conn = conn
        
    def get_file_state(self, hashval):
        pass
    
    def set_file_state(self, hashval, attrs):
        pass


class Persistor:
    def create_persistor(self, config):
        location = config.string('location')
        conn = sqlite3.connect(location)
        return SQLiteBasedPersistor(conn)
