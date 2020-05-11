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

"""Component that deduplicates the input list"""


class DeduplicationComponent:
    """
    DeduplicationComponent

    Description:
        Removes hashes from the input that have already been processed, as determined by the
        contents of the state manager.
    """
    def __init__(self, config, state_manager):
        """Constructor"""
        # simple dependency-injection technique
        self._config = config
        self._state_manager = state_manager

    def deduplicate(self, list_input):
        """
        Remove hashes from the input that have already been processed, as determined by the state manager.

        Args:
            list_input (list): List of hashes to be processed (coming from command line input)

        Returns:
            list: Another list of hashes, with all the hashes that have already been processed
                  removed from it.  If no hashes remain after the processed ones are removed,
                  returns an empty list.

        """
        engine_name = self._config.string("engine.name")
        # Use simple set-difference implementation unless we need to implement something more powerful,
        # like merge-join technique
        input_set = {item.casefold() for item in list_input}
        existset = set(self._state_manager.get_previous_hashes(engine_name))
        return list(input_set - existset)
