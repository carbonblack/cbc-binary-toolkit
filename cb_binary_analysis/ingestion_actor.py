# -*- coding: utf-8 -*-

"""Base for ingestion actor"""

from thespian.actors import Actor


class IngestionActor(Actor):
    """IngestionActor"""
    def receiveMessage(self, message, sender):
        """Entry Point"""
        self.send(sender, 'Hello World')
