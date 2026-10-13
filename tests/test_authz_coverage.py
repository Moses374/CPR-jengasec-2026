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


def _operations():
    for route in app.routes:
        methods = getattr(route, "methods", None)
        dependant = getattr(route, "dependant", None)
        if methods is None or dependant is None:
            continue
        for method in sorted(methods - {"HEAD", "OPTIONS"}):
            yield method, route.path, dependant


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

    path = Path(__file__).resolve().parent.parent / "migrations" / "versions" / "0004_auth.py"
    spec = importlib.util.spec_from_file_location("m0004", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert tuple(module.ROLES) == auth.ROLES
