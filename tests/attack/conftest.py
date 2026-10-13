"""Attack tests against a RUNNING stack (docs/DECISIONS.md, E4). Skipped unless ATTACK_BASE_URL is set,
so pytest in CI and on laptops stays as it was.

    docker compose up --build -d
    ATTACK_BASE_URL=http://localhost:8080 python -m pytest tests/attack -q

Point this at your own docker compose stack only. Never at the platform deployment before the freeze:
the database is snapshotted at freeze, and test data created there would be in it.
"""

import os
import uuid

import httpx
import pytest

# Reachable without a token. Login is found by name below; everything else in /openapi.json must demand one.
PUBLIC_PATHS = {"/healthz", "/readyz", "/openapi.json"}


def pytest_configure(config):
    config.addinivalue_line("markers", "attack: runs against a live stack (set ATTACK_BASE_URL)")


def pytest_collection_modifyitems(config, items):
    if os.environ.get("ATTACK_BASE_URL"):
        return
    skip = pytest.mark.skip(reason="set ATTACK_BASE_URL to run attack tests against a live stack")
    for item in items:
        if "tests/attack" in item.nodeid.replace("\\", "/"):
            item.add_marker(skip)


@pytest.fixture(scope="session")
def base_url():
    return os.environ["ATTACK_BASE_URL"].rstrip("/")


@pytest.fixture(scope="session")
def http(base_url):
    with httpx.Client(base_url=base_url, timeout=15, follow_redirects=False) as client:
        yield client


@pytest.fixture(scope="session")
def operations(http):
    """[(METHOD, path)] for every operation the API publishes, minus login."""
    spec = http.get("/openapi.json").json()
    ops = []
    for path, item in spec.get("paths", {}).items():
        for method in item:
            if method.lower() in {"get", "post", "put", "patch", "delete"} and not path.rstrip("/").endswith("login"):
                ops.append((method.upper(), path))
    return ops


def _concrete(path: str) -> str:
    out = path
    while "{" in out:
        start, end = out.index("{"), out.index("}")
        out = out[:start] + str(uuid.uuid4()) + out[end + 1:]
    return out


@pytest.fixture(scope="session")
def concrete():
    """Fills the {placeholders} of a path with random UUIDs."""
    return _concrete
