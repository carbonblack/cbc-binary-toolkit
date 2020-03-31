# -*- coding: utf-8 -*-

"""Component that deduplicates the input list"""


class DeduplicationComponent():
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
        Remove hashes from the input that have already been processed, as determined by the
        contents of the state manager.

        Args:
            list_input (list): List of hashes to be processed (coming from input)

        Returns:
            list: Another list of hashes, with all the hashes that have already been processed
            removed from it.  If no hashes remain after the processed ones are removed, returns
            an empty list.
        """
        engine_name = self._config.string("engine.name")
        # Use simple set-difference implementation unless we need to implement something more powerful,
        # like merge-join technique
        inputset = set(list_input)
        existset = set(self._state_manager.get_previous_hashes(engine_name))
        return list(inputset - existset)
