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

"""
Binary analysis tool for managing and submitting hashes

This class performs binary analysis on a series of hashes passed in on the command line.
"""

import os
import sys
import argparse
import logging
import traceback

from datetime import datetime

from cbc_binary_toolkit import cli_input
from cbc_binary_toolkit import EngineResults
from cbc_binary_toolkit.config import Config
from cbc_binary_toolkit.deduplication_component import DeduplicationComponent
from cbc_binary_toolkit.ingestion_component import IngestionComponent
from cbc_binary_toolkit.engine import LocalEngineManager
from cbc_binary_toolkit.state import StateManager

from cbapi import CbThreatHunterAPI

DEFAULT_LOG_LEVEL = "INFO"

LOG_LEVELS = {
    'CRITICAL': logging.CRITICAL,
    'ERROR': logging.ERROR,
    'WARNING': logging.WARNING,
    'INFO': logging.INFO,
    'DEBUG': logging.DEBUG
}

log = logging.getLogger(__name__)


class AnalysisUtility:
    """The top level analysis utility class. This is intended as an example which can be modified as needed."""
    def __init__(self, default_install):
        """Constructor for the analysis utility class"""
        self.default_install = default_install
        self.config = None
        self.cbapi = None

        # Create argument parser
        self._parser = argparse.ArgumentParser()
        self._parser.add_argument("-c", "--config", type=str, default=default_install,
                                  help="Location of the configuration file (default {0})".format(default_install))
        self._parser.add_argument("-ll", "--log-level", type=str, default="INFO",
                                  choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                                  help="The base log level (default {0})".format(DEFAULT_LOG_LEVEL))

        commands = self._parser.add_subparsers(help="Binary analysis commands", dest="command_name")

        # Analyze command parser
        analyze_command = commands.add_parser("analyze", help="Analyze a list of hashes by command line or file")
        input_type = analyze_command.add_mutually_exclusive_group(required=True)
        input_type.add_argument("-l", "--list", type=str, help="List of hashes in JSON string format")
        input_type.add_argument("-f", "--file", type=argparse.FileType('r'),
                                help="File of hashes in json or csv format")

        # Restart command parser
        commands.add_parser("restart", help="Restart a failed job and pick up where the job crashed or exited")

        # Clear command parser
        clear_command = commands.add_parser("clear", help="Clear cache of analyzed hashes. All or by timestamp")
        clear_command.add_argument("-t", "--timestamp", type=str,
                                   help="ISO 8601 date format {YYYY-MM-DD HH:MM:SS.SSS}")
        clear_command.add_argument("--force", action='store_true', help="Force clearing without prompting")
        clear_command.add_argument("-r", "--reports", action='store_true', help="Also clear any unsent reports present")

    def _init_components(self):
        """
        Initialize the components of the toolkit, injecting their dependencies as they're created.

        Returns:
            dict: A dict containing all the references to the top-level components.

        """
        try:
            state_manager = StateManager(self.config)
        except:
            log.error("Failed to create State Manager. Check your configuration")
            log.debug(traceback.format_exc())
            state_manager = None

        cbth = self.cbapi
        if cbth is None:
            cbth = CbThreatHunterAPI(url=self.config.get("carbonblackcloud.url"),
                                     org_key=self.config.get("carbonblackcloud.org_key"),
                                     token=self.config.get("carbonblackcloud.api_token"),
                                     ssl_verify=self.config.get("carbonblackcloud.ssl_verify"))

        deduplicate = DeduplicationComponent(self.config, state_manager)
        ingest = IngestionComponent(self.config, cbth, state_manager)

        results_engine = EngineResults(self.config.get("engine.name"), state_manager, cbth)
        if self.config.get("engine.type") == "local":
            try:
                engine_manager = LocalEngineManager(self.config)
            except:
                log.error("Failed to create Local Engine Manager. Check your configuration")
                log.debug(traceback.format_exc())
                engine_manager = None
        else:
            engine_manager = None

        return {
            "deduplicate": deduplicate,
            "ingest": ingest,
            "engine_manager": engine_manager,
            "results_engine": results_engine,
            "state_manager": state_manager,
            "success": True if state_manager is not None and engine_manager is not None else False
        }

    def _yes_or_no(self, question):
        """
        Request confirmation of something from the user.

        Args:
            question (str): Question to ask the user.

        Returns:
            boolean: True if the user answered Yes, False if they answered No.

        """
        reply = str(input(f"{question}: (y/n)")).lower().strip()
        if reply[0] == 'y':
            return True
        if reply[0] == 'n':
            return False
        else:
            log.error("Invalid: please use y/n")
            return self._yes_or_no(question)

    def _any_reports_present(self, state_manager):
        """
        Returns True if there are any report items present in the database.

        Args:
            state_manager (StateManager): The state manager object created by the clear process.

        Returns:
            (boolean) True if there are any report items present in the database, False if not.

        """
        for i in range(1, 11):
            items = state_manager.get_current_report_items(i, self.config.get("engine.name"))
            if len(items) > 0:
                return True
        return False

    def _process_metadata(self, components, metadata_list):
        """
        Analyze a list of metadata through the analysis engine and report on the results.

        The back end to the analyze and restart commands.

        Args:
            components (dict): Dict containing all the component references as returned from _init_components.
            metadata_list (list): List of metadata objects to be analyzed.

        """
        for metadata in metadata_list:
            response = components["engine_manager"].analyze(metadata)
            components["results_engine"].receive_response(response)

        log.info('Analysis Completed')
        if self.config.get("engine.feed_id"):
            components["results_engine"].send_reports(self.config.get("engine.feed_id"))
        else:
            log.info("Feed publishing disabled. Specify a feed_id to enable")

    def _analyze_command(self, args, components):
        """
        Implements the "analyze" command to analyze a list of hashes.

        Args:
            args (Namespace): The command-line arguments as parsed.
            components (dict): Dict containing all the component references as returned from _init_components.

        """
        if args.file is not None:
            hash_group = cli_input.read_csv(args.file)
        else:
            hash_group = cli_input.read_json(args.list)

        before = len(hash_group)
        log.info("Checking for previously executed binaries")
        hash_group = components["deduplicate"].deduplicate(hash_group)
        if before > len(hash_group):
            log.info(f"Found {before - len(hash_group)} binaries that have already been analyzed")

        metadata_list = components["ingest"].fetch_metadata(hash_group)
        self._process_metadata(components, metadata_list)

    def _restart_command(self, components):
        """
        Implements the "restart" command to resume analysis on already-ingested hash values.

        Args:
            components (dict): Dict containing all the component references as returned from _init_components.

        """
        components["results_engine"].reload()
        metadata_list = components["ingest"].reload()
        self._process_metadata(components, metadata_list)

    def main(self, cmdline_args):
        """
        Entry point for the analysis utility.

        Args:
            cmdline_args (list): Command-line argument strings to be parsed.

        Returns:
            int: Return code from the utility (0=success, nonzero=failure).

        """
        args = self._parser.parse_args(cmdline_args)
        logging.basicConfig(level=LOG_LEVELS[args.log_level])

        if args.log_level != "DEBUG":
            sys.tracebacklimit = 0

        log.debug("Started: {}".format(datetime.now()))

        if args.command_name is None:
            print(
                "usage: cbc-binary-analysis [-h] [-c CONFIG]\n"
                "                           [-ll {DEBUG,INFO,WARNING,ERROR,CRITICAL}]\n"
                "                           {analyze,restart,clear} ...\n"
                "cbc-binary-analysis: error: the following arguments are required: command_name")
            return

        try:
            if self.config is None:
                if args.config != self.default_install:
                    self.config = Config.load_file(args.config)
                elif self.default_install == "ERROR":
                    # Exit if default_install was not found
                    log.error("Exiting as default example config file could not be "
                              "found and no alternative was specified")
                    return 1
                else:
                    log.info(f"Attempting to load config from {self.default_install}")
                    self.config = Config.load_file(self.default_install)

            if args.command_name == "analyze":
                components = self._init_components()
                if components["success"]:
                    log.info("Analyzing hashes")
                    self._analyze_command(args, components)

            elif args.command_name == "clear":
                timestamp = args.timestamp
                if timestamp is None:
                    timestamp = str(datetime.now())
                if not (args.force or self._yes_or_no(f"Confirm you want to clear runs prior to {timestamp}")):
                    log.info("Clear canceled")
                    return

                # Clear previous states
                try:
                    state_manager = StateManager(self.config)
                except:
                    log.error("Failed to create State Manager. Check your configuration")
                    log.debug(traceback.format_exc())
                else:
                    log.info("Clearing cache")
                    state_manager.prune(timestamp)
                    if args.reports and self._any_reports_present(state_manager):
                        if args.force or self._yes_or_no("Confirm you want to clear unsent report items"):
                            log.info("Clearing report items")
                            for i in range(1, 11):
                                state_manager.clear_report_items(i, self.config.get("engine.name"))

            elif args.command_name == "restart":
                components = self._init_components()
                if components["success"]:
                    log.info("Restarting")
                    self._restart_command(components)

            log.debug("Finished: {}".format(datetime.now()))
            return 0
        except Exception:
            log.error(traceback.format_exc())
            return 1


def main():
    """Universal Entry Point"""
    if "cbc-binary-toolkit" in os.path.dirname(os.path.realpath(__file__)):
        default_install = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                       "../../../config/binary-analysis-config.yaml.example")
    else:
        starting_dir = (os.path.dirname(os.path.realpath(__file__)), "")
        config_example_dir = "carbonblackcloud/binary-toolkit/binary-analysis-config.yaml.example"

        # Try and navigate up and find example config file
        while starting_dir[0] != "" and starting_dir[0] != "/":
            if os.path.exists(os.path.join(starting_dir[0], config_example_dir)):
                break
            starting_dir = os.path.split(starting_dir[0])

        if starting_dir[0] == "" or starting_dir[0] == "/":
            default_install = "ERROR"
        else:
            default_install = os.path.join(starting_dir[0], config_example_dir)

    AnalysisUtility(default_install).main(sys.argv[1:])


if __name__ == '__main__':
    sys.exit(main())
