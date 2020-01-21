# -*- coding: utf-8 -*-

"""Unit tests for the ingestion actor"""

import pytest
from thespian.actors import ActorSystem
from cb_binary_analysis.ingestion_actor import IngestionActor


@pytest.fixture
def actor():
    """Creates actor to unit test"""
    return ActorSystem().createActor(IngestionActor)


def test_receiveMessage_ask(actor):
    """Test receiveMessage"""
    greeting = ActorSystem().ask(actor, 'Hello', 1)
    assert greeting == "Hello World"


def test_receiveMessage_tell(actor):
    """Test receiveMessage"""
    ActorSystem().tell(actor, 'Hello')
    greeting = ActorSystem().listen()
    assert greeting == "Hello World"
