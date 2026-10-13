"""Attacks that need no login and no knowledge of the final API: A14, A15 and A18 of docs/DECISIONS.md (E4).

They read /openapi.json and attack whatever it lists, so they grow with the API and need no edits.
"""

import time

import pytest

pytestmark = pytest.mark.attack

LEAKS = ("Traceback", "sqlalchemy", "psycopg", "uvicorn", "starlette", 'File "', "postgres", "SELECT ", "INSERT ")


def no_leak(response):
    body = response.text
    assert not any(marker.lower() in body.lower() for marker in LEAKS), f"internals in the body: {body[:200]}"
    assert "server" not in response.headers


def test_a18_every_operation_refuses_a_caller_with_no_token(http, operations, concrete):
    wrong = []
    for method, path in operations:
        r = http.request(method, concrete(path), json={} if method != "GET" else None)
        if r.status_code != 401:
            wrong.append(f"{method} {path} -> {r.status_code} (expected 401)")
        no_leak(r)
    assert not wrong, "Default deny is broken:\n" + "\n".join(wrong)


@pytest.mark.parametrize("header", [
    "Bearer garbage", "Bearer ", "Bearer " + "A" * 5000, "Basic YWRtaW46YWRtaW4=", "bearer null", "Token abc",
])
def test_a5_every_operation_refuses_a_garbage_token(http, operations, concrete, header):
    wrong = []
    for method, path in operations:
        r = http.request(method, concrete(path), headers={"Authorization": header}, json={} if method != "GET" else None)
        if r.status_code != 401:
            wrong.append(f"{method} {path} -> {r.status_code}")
        no_leak(r)
    assert not wrong, "A bad token got further than 401:\n" + "\n".join(wrong)


def test_a14_errors_leak_nothing(http):
    for response in (
        http.get("/does-not-exist"),
        http.post("/healthz"),
        http.request("DELETE", "/openapi.json"),
        http.get("/healthz", params={"x": "' OR 1=1--"}),
        http.post("/openapi.json", content=b"{not json", headers={"Content-Type": "application/json"}),
        http.get("/%00"),
    ):
        assert response.status_code < 500
        no_leak(response)


def test_security_headers_are_present_and_the_server_is_not_named(http):
    r = http.get("/healthz")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert "server" not in r.headers
    assert http.get("/docs").status_code == 404 and http.get("/redoc").status_code == 404


def test_a15_a_huge_body_is_handled_quickly_and_without_a_server_error(http, operations, concrete):
    posts = [path for method, path in operations if method == "POST"]
    if not posts:
        pytest.skip("no POST operation published yet")
    started = time.monotonic()
    r = http.post(concrete(posts[0]), content=b'{"memo":"' + b"A" * 2_000_000 + b'"}',
                  headers={"Content-Type": "application/json"})
    assert r.status_code < 500 and r.status_code in (401, 413, 422)
    assert time.monotonic() - started < 5
    no_leak(r)
