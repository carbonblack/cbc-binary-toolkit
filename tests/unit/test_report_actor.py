# -*- coding: utf-8 -*-

"""Unit tests for the ingestion actor"""

import pytest
from thespian.actors import ActorSystem, ActorExitRequest
from cb_binary_analysis.report_actor import ReportActor


@pytest.fixture(scope="function")
def actor():
    """Creates actor to unit test"""
    actor = ActorSystem().createActor(ReportActor)
    yield actor
    ActorSystem().ask(actor, ActorExitRequest())


def test_receiveMessage_ask(actor):
    """Test receiveMessage"""
    greeting = ActorSystem().ask(actor, 'Hello', 1)
    assert greeting == "Valid"


def test_receiveMessage_tell(actor):
    """Test receiveMessage"""
    ActorSystem().tell(actor, 'Hello')
    greeting = ActorSystem().listen()
    assert greeting == "Valid"
