# -*- coding: utf-8 -*-

"""Unit tests for the ingestion actor"""

import pytest
from thespian.actors import ActorSystem, ActorExitRequest
from cb_binary_analysis.ingestion_actor import IngestionActor


@pytest.fixture(scope="function")
def actor():
    """Creates actor to unit test"""
    actor = ActorSystem().createActor(IngestionActor)
    yield actor
    ActorSystem().ask(actor, ActorExitRequest())


@pytest.mark.parametrize("input", [
    [],
    [{'sha256': ['405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4'], 'expiration_seconds': 3600}],
    [{'sha256': ['405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4'], 'expiration_seconds': 3600},
     {'sha256': ['405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4'], 'expiration_seconds': 3600}],
])
def test_receiveMessage_ask(actor, input):
    """Test receiveMessage"""
    for item in input:
        completion = ActorSystem().ask(actor, item, 10)
        assert "Completed" in completion


@pytest.mark.parametrize("input", [
    [],
    [{'sha256': ['405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4'], 'expiration_seconds': 3600}],
    [{'sha256': ['405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4'], 'expiration_seconds': 3600},
     {'sha256': ['405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4'], 'expiration_seconds': 3600}],
])
def test_receiveMessage_tell(actor, input):
    """Test receiveMessage"""
    for item in input:
        ActorSystem().tell(actor, item)
    completion = ActorSystem().listen()
    assert "Completed" in completion
