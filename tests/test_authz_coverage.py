"""Default deny, checked without a database (docs/DECISIONS.md, T7).

Every route except the public ones must depend on app.auth.current_user, directly or through
require_role. A new route that forgets its dependency fails the build here, before it can ship.
"""

import pytest

from app import auth
from app.main import app

PUBLIC = {
    ("GET", "/healthz"), ("GET", "/readyz"), ("GET", "/openapi.json"),
    ("POST", "/api/v1/auth/login"),
}


def _depends_on_current_user(dependant) -> bool:
    for dep in dependant.dependencies:
        if dep.call is auth.current_user or _depends_on_current_user(dep):
            return True
    return False


def _routes(routes):
    """Every route, including those inside included routers. FastAPI 0.140+ no longer flattens
    include_router() into app.routes; it wraps each router (original_router), so walk into it."""
    for route in routes:
        inner = getattr(route, "original_router", None)
        if inner is not None:
            yield from _routes(inner.routes)
        else:
            yield route


def _operations():
    for route in _routes(app.routes):
        methods = getattr(route, "methods", None)
        dependant = getattr(route, "dependant", None)
        if methods is None or dependant is None:
            continue
        for method in sorted(methods - {"HEAD", "OPTIONS"}):
            yield method, route.path, dependant


def test_every_published_operation_is_checked():
    """Guard for the test itself: if a framework change hides routes from _operations(), fail here
    instead of silently checking fewer routes (this happened once, on the FastAPI 0.140 upgrade)."""
    published = {(m.upper(), path) for path, item in app.openapi()["paths"].items() for m in item}
    walked = {(m, path) for m, path, _ in _operations()}
    assert published <= walked, f"routes not checked for an auth dependency: {sorted(published - walked)}"


def test_openapi_route_is_listed_even_though_it_has_no_dependant():
    # Starlette serves /openapi.json outside FastAPI's dependants; it is public by design.
    assert ("GET", "/openapi.json") in PUBLIC


@pytest.mark.parametrize("method,path,dependant", list(_operations()), ids=lambda v: v if isinstance(v, str) else "")
def test_route_is_public_or_requires_a_user(method, path, dependant):
    if (method, path) in PUBLIC:
        return
    assert _depends_on_current_user(dependant), f"{method} {path} has no auth dependency"


def test_require_role_rejects_unknown_roles():
    with pytest.raises(ValueError):
        auth.require_role("superuser")
    with pytest.raises(ValueError):
        auth.require_role()


def test_roles_match_the_database_check():
    import importlib.util
    from pathlib import Path

    path = Path(__file__).resolve().parent.parent / "migrations" / "versions" / "0005_auth.py"
    spec = importlib.util.spec_from_file_location("m0004", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert tuple(module.ROLES) == auth.ROLES
