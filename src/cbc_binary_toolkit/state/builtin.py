# -*- coding: utf-8 -*-

# *******************************************************
# Copyright (c) VMware, Inc. 2020. All Rights Reserved.
# SPDX-License-Identifier: MIT
# *******************************************************
# *
# * DISCLAIMER. THIS PROGRAM IS PROVIDED TO YOU "AS IS" WITHOUT
# * WARRANTIES OR CONDITIONS OF ANY KIND, WHETHER ORAL OR WRITTEN,
# * EXPRESS OR IMPLIED. THE AUTHOR SPECIFICALLY DISCLAIMS ANY IMPLIED
# * WARRANTIES OR CONDITIONS OF MERCHANTABILITY, SATISFACTORY QUALITY,
# * NON-INFRINGEMENT AND FITNESS FOR A PARTICULAR PURPOSE.

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
        self._cursor_factory = sqlite3.Cursor

    def force_close(self):
        """
        Forces the persistor to close. This should only be called from test code.
        """
        self._conn.close()
        self._conn = None

    def set_checkpoint(self, binary_hash, engine_name, checkpoint_name, checkpoint_time=None):
        """
        Set a checkpoint on a binary hash/engine combination.

        Args:
            binary_hash (str): The hash value to set in the database.
            engine_name (str): The engine value to set in the database.
            checkpoint_name (str): The name of the checkpoint to set.
            checkpoint_time (str): The timestamp to set the checkpoint time to.  Assumed to be in
                                   local time.  Not normally used except in test code.

        """
        try:
            cursor = self._conn.cursor(self._cursor_factory)
            if checkpoint_time is None:
                stmt = """
                UPDATE run_state SET checkpoint_name = ?, checkpoint_time = datetime('now')
                    WHERE file_hash = ? AND engine_name = ?;
                """
                cursor.execute(stmt, (checkpoint_name, binary_hash, engine_name))
                if cursor.rowcount == 0:
                    stmt = """
                    INSERT INTO run_state(file_hash, engine_name, checkpoint_name, checkpoint_time)
                        VALUES (?, ?, ?, datetime('now'));
                    """
                    cursor.execute(stmt, (binary_hash, engine_name, checkpoint_name))
            else:
                stmt = """
                UPDATE run_state SET checkpoint_name = ?, checkpoint_time = datetime(?, 'utc')
                    WHERE file_hash = ? AND engine_name = ?;
                """
                cursor.execute(stmt, (checkpoint_name, checkpoint_time, binary_hash, engine_name))
                if cursor.rowcount == 0:
                    stmt = """
                    INSERT INTO run_state(file_hash, engine_name, checkpoint_name, checkpoint_time)
                        VALUES (?, ?, ?, datetime(?, 'utc'));
                    """
                    cursor.execute(stmt, (binary_hash, engine_name, checkpoint_name, checkpoint_time))
            self._conn.commit()
        except sqlite3.OperationalError as e:
            log.error("OperationalError in set_checkpoint: %s" % (e,))
        finally:
            cursor.close()

    def get_previous_hashes(self, engine_name):
        """
        Returns a sorted list of all previously-completed hashes.

        Args:
            engine_name (str): The engine value to look up in the database.

        Returns:
            list: A list of all the hashes that have been marked as "done" for that engine. This list
                  will be in sorted order.

        """
        try:
            cursor = self._conn.cursor(self._cursor_factory)
            stmt = """
            SELECT file_hash FROM run_state WHERE engine_name = ? AND checkpoint_name = 'DONE'
                ORDER BY file_hash;
            """
            return_list = []
            for row in cursor.execute(stmt, (engine_name,)):
                return_list.append(row[0])
            return return_list
        except sqlite3.OperationalError as e:
            log.error("OperationalError in get_previous_hashes: %s" % (e,))
            return []
        finally:
            cursor.close()

    def get_unfinished_hashes(self, engine_name):
        """
        Returns a sorted list of all not-completed hashes.

        Args:
            engine_name (str): The engine value to look up in the database.

        Returns:
            list: A list of all the hashes that are in the database but have not been marked as "done"
                  for that engine.  This list is in the form of tuples, the first element of which is
                  the hash, the second element of which is the last known checkpoint.

        """
        try:
            cursor = self._conn.cursor(self._cursor_factory)
            stmt = """
            SELECT file_hash, checkpoint_name FROM run_state
                WHERE engine_name = ? AND checkpoint_name <> 'DONE';
            """
            return_list = []
            for row in cursor.execute(stmt, (engine_name,)):
                return_list.append((row[0], row[1]))
            return return_list
        except sqlite3.OperationalError as e:
            log.error("OperationalError in get_unfinished_hashes: %s" % (e,))
            return []
        finally:
            cursor.close()

    def prune(self, timestamp):
        """
        Erases all entries from the database older than a specified time.

        Args:
            timestamp (str): The basic timestamp (ISO 8601 format). Assumed to be in local time.
                              Everything older than this will be erased.

        """
        try:
            cursor = self._conn.cursor(self._cursor_factory)
            stmt = """
            DELETE FROM run_state WHERE julianday(checkpoint_time) < julianday(?, 'utc');
            """
            cursor.execute(stmt, (timestamp, ))
            cursor.close()
            self._conn.commit()
            self._conn.execute("VACUUM;")
        except sqlite3.OperationalError as e:
            log.error("OperationalError in prune: %s" % (e,))

    def add_report_item(self, severity, engine_name, data):
        """
        Adds a new report item (IOC record) to the current stored list.

        Args:
            severity (int): The severity level (1-10).
            engine_name (str): The engine value to store this data for.
            data (dict): The data item to be stored.

        """
        try:
            cursor = self._conn.cursor(self._cursor_factory)
            stmt = """
            INSERT INTO report_item (severity, engine_name, data)
                VALUES (?, ?, ?);
            """
            cursor.execute(stmt, (severity, engine_name, json.dumps(data)))
            self._conn.commit()
        except sqlite3.OperationalError as e:
            log.error("OperationalError in add_report_item: %s" % (e,))
        finally:
            cursor.close()

    def get_current_report_items(self, severity, engine_name):
        """
        Returns all current report items (IOC records) in the given list.

        Args:
            severity (int): The severity level (1-10).
            engine_name (str): The engine value to return data for.

        Returns:
            list: A list of dicts, each of which represents a report item.

        """
        try:
            cursor = self._conn.cursor(self._cursor_factory)
            stmt = "SELECT data FROM report_item WHERE severity = ? AND engine_name = ?;"
            return_list = []
            for row in cursor.execute(stmt, (severity, engine_name)):
                return_list.append(json.loads(row[0]))
            return return_list
        except sqlite3.OperationalError as e:
            log.error("OperationalError in get_current_report_items: %s" % (e,))
            return []
        finally:
            cursor.close()

    def clear_report_items(self, severity, engine_name):
        """
        Clears all report items (IOC records) from a given list.

        Args:
            severity (int): The severity level (1-10).
            engine_name (str): The engine value to clear data for.

        """
        try:
            cursor = self._conn.cursor(self._cursor_factory)
            stmt = "DELETE FROM report_item WHERE severity = ? AND engine_name = ?;"
            cursor.execute(stmt, (severity, engine_name))
            self._conn.commit()
        except sqlite3.OperationalError as e:
            log.error("OperationalError in clear_report_items: %s" % (e,))
        finally:
            cursor.close()


class Persistor(BasePersistorFactory):
    """Default implementation of the persistor factory that uses SQLite to store information."""
    def create_persistor(self, config):
        """
        Creates a new persistor object.

        Args:
            config (Config): The configuration section for the persistence parameters.

        Returns:
            Persistor: The new persistor object.

        """
        location = config.string('location')
        conn = sqlite3.connect(location, check_same_thread=False)
        self._setup_database(conn)
        return SQLiteBasedPersistor(conn)

    def _setup_database(self, conn):
        """
        Internal: Sets up the database correctly.

        Args:
            conn (Connection): The database connection object.

        """
        cursor = conn.cursor()
        stmt = """
        CREATE TABLE IF NOT EXISTS run_state (
            file_hash TEXT NOT NULL,
            engine_name TEXT NOT NULL,
            checkpoint_name TEXT NOT NULL,
            checkpoint_time TEXT
        );
        """
        cursor.execute(stmt)
        stmt = """
        CREATE INDEX IF NOT EXISTS run_hashes ON run_state (engine_name, file_hash);
        """
        cursor.execute(stmt)
        stmt = """
        CREATE INDEX IF NOT EXISTS run_checkpoints ON run_state (engine_name, checkpoint_name);
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
