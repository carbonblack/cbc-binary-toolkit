# -*- coding: utf-8 -*-

"""Default implementation of the persistor that uses SQLite."""


import sqlite3
import json
import logging
from .manager import BasePersistor, BasePersistorFactory


log = logging.getLogger(__name__)


class SQLiteBasedPersistor(BasePersistor):
    """Default implementation of the persistor that uses SQLite to store information."""
    def __init__(self, conn):
        """Constructor"""
        self._conn = conn

    def get_file_state(self, binary_hash, engine=None):
        """
        Get the stored file state for a specified hash value.

        :param binary_hash str: The hash value to look up in the database.
        :param engine str: (Optional) The engine value to look up in the database.
        :return: A dict containing the file information, or None if not found.
        """
        try:
            cursor = self._conn.cursor()
            if engine:
                stmt = """
                SELECT rowid, file_size, file_name, os_type, engine_name, time_sent, time_returned, time_published
                    FROM run_state
                    WHERE file_hash = ? AND engine_name = ?
                    ORDER BY max(julianday(time_sent), julianday(coalesce(time_returned, time_sent)),
                                 julianday(coalesce(time_published, time_returned, time_sent))) DESC;
                """
                cursor.execute(stmt, (binary_hash, engine))
            else:
                stmt = """
                SELECT rowid, file_size, file_name, os_type, engine_name, time_sent, time_returned, time_published
                    FROM run_state
                    WHERE file_hash = ?
                    ORDER BY max(julianday(time_sent), julianday(coalesce(time_returned, time_sent)),
                                 julianday(coalesce(time_published, time_returned, time_sent))) DESC;
                """
                cursor.execute(stmt, (binary_hash,))
            row = cursor.fetchone()
            if not row:
                return None
            value = {'persist_id': row[0], 'file_hash': binary_hash, 'file_size': row[1], 'file_name': row[2],
                     'os_type': row[3], 'engine_name': row[4]}
            if row[5]:
                value['time_sent'] = row[5]
            if row[6]:
                value['time_returned'] = row[6]
            if row[7]:
                value['time_published'] = row[7]
            return value
        except sqlite3.OperationalError as e:
            log.error("OperationalError in get_file_state: %s" % (e,))
            return None

    def set_file_state(self, binary_hash, attrs, persist_id=None):
        """
        Set the stored file state for a specified hash value.

        :param binary_hash str: The hash value to set in the database.
        :param attrs dict: The attributes to set as part of the hash value entry.
        :param persist_id int: The persistence ID of the existing record we're modifying (optional).
        :return: The persistence ID of the database row, either new or existing.
        """
        try:
            cursor = self._conn.cursor()
            if persist_id:
                stmt = """
                UPDATE run_state
                    SET time_sent = ifnull(?, time_sent), time_returned = ifnull(?, time_returned),
                        time_published = ifnull(?, time_published)
                    WHERE rowid = ? AND file_hash = ?;
                """
                cursor.execute(stmt, (attrs.get('time_sent', None), attrs.get('time_returned', None),
                                      attrs.get('time_published', None), persist_id, binary_hash))
                return persist_id
            else:
                stmt = """
                INSERT INTO run_state(file_hash, file_size, file_name, os_type, engine_name, time_sent,
                                      time_returned, time_published)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """
                cursor.execute(stmt, (binary_hash, attrs['file_size'], attrs['file_name'], attrs['os_type'],
                                      attrs['engine_name'], attrs.get('time_sent', None),
                                      attrs.get('time_returned', None), attrs.get('time_published', None)))
                return cursor.lastrowid
        except sqlite3.OperationalError as e:
            log.error("OperationalError in set_file_state: %s" % (e,))
            return None

    def get_unfinished_states(self, engine=None):
        """
        Returns all states not marked as "analysis finished" (possibly for a single engine).

        :param engine str: (Optional) The engine value to look up in the database.
        :return: A list of dicts containing all unfinished file information. Returns an empty list if none present.
        """
        try:
            cursor = self._conn.cursor()
            if engine:
                stmt = """
                SELECT rowid, file_hash, file_size, file_name, os_type, engine_name, time_sent, time_returned
                    FROM run_state
                    WHERE time_published IS NULL AND engine_name = ?
                    ORDER BY max(julianday(time_sent), julianday(coalesce(time_returned, time_sent)),
                                 julianday(coalesce(time_published, time_returned, time_sent))) DESC;
                """
                output_iterator = cursor.execute(stmt, (engine, ))
            else:
                stmt = """
                SELECT rowid, file_hash, file_size, file_name, os_type, engine_name, time_sent, time_returned
                    FROM run_state
                    WHERE time_published IS NULL
                    ORDER BY max(julianday(time_sent), julianday(coalesce(time_returned, time_sent)),
                                 julianday(coalesce(time_published, time_returned, time_sent))) DESC;
                """
                output_iterator = cursor.execute(stmt)
            return_list = []
            for row in output_iterator:
                value = {'persist_id': row[0], 'file_hash': row[1], 'file_size': row[2], 'file_name': row[3],
                         'os_type': row[4], 'engine_name': row[5]}
                if row[6]:
                    value['time_sent'] = row[6]
                if row[7]:
                    value['time_returned'] = row[7]
                return_list.append(value)
            return return_list
        except sqlite3.OperationalError as e:
            log.error("OperationalError in get_unfinished_states: %s" % (e,))
            return []

    def get_num_stored_states(self):
        """
        Returns the number of stored states in the persistence manager for each known engine.

        :return: A dict with engine names as keys and count of results for each engine as values.
        """
        try:
            cursor = self._conn.cursor()
            stmt = "SELECT engine_name, count(*) FROM run_state GROUP BY engine_name;"
            output_iterator = cursor.execute(stmt)
            return_dict = {}
            for row in output_iterator:
                return_dict[row[0]] = row[1]
            return return_dict
        except sqlite3.OperationalError as e:
            log.error("OperationalError in get_num_stored_states: %s" % (e,))
            return {}

    def prune(self, timestamp):
        """
        Erases all entries from the database older than a specified time.

        :param timestamp str: The basic timestamp. Everything older than this will be erased.
        """
        try:
            cursor = self._conn.cursor()
            stmt = """
            DELETE FROM run_state
                WHERE max(julianday(time_sent), julianday(coalesce(time_returned, time_sent)),
                          julianday(coalesce(time_published, time_returned, time_sent))) < julianday(?);
            """
            cursor.execute(stmt, (timestamp, ))
            cursor.close()
            self._conn.commit()
            self._conn.execute("VACUUM;")
        except sqlite3.OperationalError as e:
            log.error("OperationalError in prune: %s" % (e,))

    def add_report_item(self, severity, engine, data):
        """
        Adds a new report item (IOC record) to the current stored list.

        :param severity int: The severity level (1-10).
        :param engine str: The engine value to store this data for.
        :param data dict: The data item to be stored.
        """
        try:
            cursor = self._conn.cursor()
            stmt = """
            INSERT INTO report_item (severity, engine_name, data)
                VALUES (?, ?, ?);
            """
            cursor.execute(stmt, (severity, engine, json.dumps(data)))
        except sqlite3.OperationalError as e:
            log.error("OperationalError in add_report_item: %s" % (e,))

    def get_current_report_items(self, severity, engine):
        """
        Returns all current report items (IOC records) in the given list.

        :param severity int: The severity level (1-10).
        :param engine str: The engine value to return data for.
        :return: A list of dicts, each of which represents a report item.
        """
        try:
            cursor = self._conn.cursor()
            stmt = "SELECT data FROM report_item WHERE severity = ? AND engine_name = ?;"
            return_list = []
            for row in cursor.execute(stmt, (severity, engine)):
                return_list.append(json.loads(row[0]))
            return return_list
        except sqlite3.OperationalError as e:
            log.error("OperationalError in get_current_report_items: %s" % (e,))
            return []

    def clear_report_items(self, severity, engine):
        """
        Clears all report items (IOC records) from a given list.

        :param severity int: The severity level (1-10).
        :param engine str: The engine value to clear data for.
        """
        try:
            cursor = self._conn.cursor()
            stmt = "DELETE FROM report_item WHERE severity = ? AND engine_name = ?;"
            cursor.execute(stmt, (severity, engine))
        except sqlite3.OperationalError as e:
            log.error("OperationalError in clear_report_items: %s" % (e,))


class Persistor(BasePersistorFactory):
    """Default implementation of the persistor factory that uses SQLite to store information."""
    def create_persistor(self, config):
        """
        Creates a new persistor object.

        :param config Config: The configuration section for the persistence parameters.
        :return: The new persistor object.
        """
        location = config.string('location')
        conn = sqlite3.connect(location)
        self._setup_database(conn)
        return SQLiteBasedPersistor(conn)

    def _setup_database(self, conn):
        """
        Internal: Sets up the database correctly.

        :param conn Connection: The database connection object.
        """
        cursor = conn.cursor()
        stmt = """
        CREATE TABLE IF NOT EXISTS run_state (
            file_hash TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            file_name TEXT NOT NULL,
            os_type TEXT NOT NULL,
            engine_name TEXT NOT NULL,
            time_sent TEXT,
            time_returned TEXT,
            time_published TEXT
        );
        """
        cursor.execute(stmt)
        stmt = """
        CREATE TABLE IF NOT EXISTS report_item (
            severity INTEGER NOT NULL,
            engine_name TEXT NOT NULL,
            data TEXT NOT NULL
        );
        """
        cursor.execute(stmt)
