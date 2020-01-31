# -*- coding: utf-8 -*-

"""
Binary analysis sdk for managing and submitting hashes

This is the entry point for the Binary Analysis SDK
"""

import argparse
import logging
import sys

from datetime import datetime

from cb_binary_analysis.config.model import Config
from cb_binary_analysis import input

logging.basicConfig(level=logging.DEBUG)  # Needs converted to configuration property
log = logging.getLogger(__name__)


def parse_args(args):
    """Create argparser"""
    parser = argparse.ArgumentParser()
    parser.add_argument("-C", "--config", type=str, default=Config.default_location,
                        help="Location of the configuration file (default {0})".format(Config.default_location))

    commands = parser.add_subparsers(help="Binary analysis commands", dest="command_name", required=True)

    # Analyze command parser
    analyze_command = commands.add_parser("analyze", help="Analyze a list of hashes by command line or file")
    input_type = analyze_command.add_mutually_exclusive_group(required=True)
    input_type.add_argument("-l", "--list", type=str, help="List of hashes in JSON string format")
    input_type.add_argument("-f", "--file", type=argparse.FileType('r'), help="File of hashes in json or csv format")

    # Clear command parser
    analyze_command = commands.add_parser("clear", help="Clear cache of analyzed hashes")
    return parser.parse_args(args)


def main():
    """Entry point"""
    log.debug("Started: {}".format(datetime.now()))

    args = parse_args(sys.argv[1:])

    # XXX config = Config.load_file(args.config) - uncomment this when we're ready to use it

    if args.command_name == "analyze":
        log.debug("Analyzing hashes")
        if args.file is not None:
            hashes = input.read_csv(args.file)
        else:
            hashes = input.read_json(args.list)

        print(hashes)

    elif args.command_name == "clear":
        log.debug("Clear cache")


if __name__ == '__main__':
    sys.exit(main())
