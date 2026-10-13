"""Checks for the platform contract. Run with: pytest"""

import json
import logging

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client():
    return TestClient(app)


class _ListHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, record):
        self.lines.append(json.loads(record.getMessage()))


@pytest.fixture
def contract_lines():
    handler = _ListHandler()
    logger = logging.getLogger("security")
    logger.addHandler(handler)
    yield lambda: handler.lines
    logger.removeHandler(handler)


def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert "server" not in r.headers


def test_openapi_served_without_ui(client):
    assert client.get("/openapi.json").status_code == 200
    assert client.get("/docs").status_code == 404


def test_every_request_writes_one_contract_line(client, contract_lines):
    client.post("/api/v1/no-such-route?token=secret", json={"amount": 1})
    lines = contract_lines()
    assert len(lines) == 1
    line = lines[0]
    assert set(line) == {"ts", "src_ip", "method", "path", "status", "user", "action"}
    assert line["path"] == "/api/v1/no-such-route"  # query string never logged
    assert line["status"] == 404
    assert line["action"] == "http.not_found"


def test_security_logger_does_not_propagate():
    assert logging.getLogger("security").propagate is False
