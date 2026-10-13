"""Pure checks for app/auth.py and app/ratelimit.py: no database, no network."""

from types import SimpleNamespace

from app import auth, ratelimit


def fake_request(header=None):
    headers = {} if header is None else {"authorization": header}
    return SimpleNamespace(headers=headers, client=SimpleNamespace(host="10.0.0.1"))


def test_password_roundtrip_uses_argon2id_with_the_agreed_parameters():
    h = auth.hash_password("correct horse battery staple")
    assert h.startswith("$argon2id$v=19$m=19456,t=2,p=1$")
    assert auth.verify_password(h, "correct horse battery staple")
    assert not auth.verify_password(h, "wrong")
    assert not auth.needs_rehash(h)


def test_malformed_stored_hash_never_verifies():
    assert not auth.verify_password("!", "anything")
    assert not auth.verify_password("", "anything")
    assert not auth.needs_rehash("!")


def test_token_is_random_and_only_its_digest_is_kept():
    t1, d1 = auth.new_token()
    t2, d2 = auth.new_token()
    assert t1 != t2 and d1 != d2
    assert len(d1) == 32 and auth.token_digest(t1) == d1
    assert t1.encode() not in d1


def test_bearer_header_parsing_is_strict():
    assert auth.bearer_token(fake_request("Bearer abc123")) == "abc123"
    assert auth.bearer_token(fake_request("bearer abc123")) == "abc123"
    for bad in [None, "", "Bearer", "Bearer ", "Basic abc", "Bearer a b", "Bearer " + "x" * 200, "Bearer café", "Token abc"]:
        assert auth.bearer_token(fake_request(bad)) is None, bad


def test_usernames_fold_case_space_and_width():
    assert auth.normalise_username("  Admin ") == "admin"
    assert auth.normalise_username("ａdmin") == "admin"  # full-width 'a' folds to 'a'
    assert len(auth.normalise_username("x" * 500)) == 64


def test_counter_keys_are_hashes_not_usernames():
    key = ratelimit.username_key("amina.wekesa")
    assert len(key) == 64 and "amina" not in key
    assert key == ratelimit.username_key("amina.wekesa")


def test_scope_params_by_role():
    def user(role):
        return auth.CurrentUser(id="00000000-0000-0000-0000-000000000001", username="u", role=role,
                                session_id="00000000-0000-0000-0000-000000000002", src_ip=None)

    assert auth.scope_params(user("customer"))["staff"] is False
    assert auth.scope_params(user("customer"))["system_ok"] is False
    for role in ("teller", "approver"):
        p = auth.scope_params(user(role))
        assert p["staff"] is True and p["system_ok"] is False
    for role in ("auditor", "admin"):
        p = auth.scope_params(user(role))
        assert p["staff"] is True and p["system_ok"] is True
