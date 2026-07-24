"""
tests/test_adapters.py
~~~~~~~~~~~~~~~~~~~~~~~
Integration tests for framework adapters (FastAPI middleware and SDK patcher).
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import aisos


def test_fastapi_middleware_allowed_request():
    app = FastAPI()
    security = aisos.init()
    security.attach(app)

    @app.get("/hello")
    def hello():
        return {"status": "ok"}

    client = TestClient(app)
    response = client.get("/hello")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_fastapi_middleware_blocked_request():
    app = FastAPI()
    security = aisos.init()
    security.attach(app)

    @app.get("/search")
    def search(q: str = ""):
        return {"q": q}

    client = TestClient(app)
    # Send SQL injection payload
    response = client.get("/search?q=SELECT%20*%20FROM%20users%20WHERE%20admin%3D1%20OR%20%271%27%3D%271%27%20--")
    assert response.status_code == 403
    assert "Request blocked by AI SOS Adaptive Security Layer" in response.json()["message"]


def test_fastapi_middleware_outbound_response_validation():
    app = FastAPI()
    security = aisos.init()
    security.attach(app)

    @app.get("/leak-secret")
    def leak_secret():
        # Backend attempts to return a leaked API key in response
        return {"config": "sk-1234567890abcdef1234567890abcdef"}

    client = TestClient(app)
    response = client.get("/leak-secret")
    # Response Validation Layer intercepts secret leak and blocks it
    assert response.status_code == 403
    assert "sensitive data leakage prevented" in response.json()["message"]
