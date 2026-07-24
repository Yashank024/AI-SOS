"""
tests/test_attach.py
~~~~~~~~~~~~~~~~~~~~~
Unit tests for AI SOS zero-code-rewrite attach() interface.
"""

import pytest
from fastapi import FastAPI

import aisos


def test_init_and_get_engine():
    engine = aisos.init()
    assert engine is not None
    assert engine.VERSION == "0.2.0"
    assert aisos.get_engine() is engine


def test_attach_fastapi():
    app = FastAPI()
    security = aisos.init()
    attached = security.attach(app)
    assert "fastapi/starlette" in attached


def test_attach_flask():
    flask = pytest.importorskip("flask")
    app = flask.Flask(__name__)
    security = aisos.init()
    attached = security.attach(app)
    assert "flask" in attached


def test_attach_sdk_targets():
    security = aisos.init()
    attached = security.attach("openai")
    assert isinstance(attached, list)


def test_enable_ai_provider():
    security = aisos.init()
    security.enable_ai(provider="OpenAI", api_key="test-key", model="gpt-4o-mini")
    assert type(security.ai_provider).__name__ == "OpenAIProvider"
