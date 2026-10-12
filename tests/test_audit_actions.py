"""Every action name in app/ comes from one vocabulary (docs/DECISIONS.md, E3).

Why a test: the stdout log line and the audit table are what detection and the judges read.
A typo ("tranfer.denied") or a name built from user input ("login.failed." + username) would hide an
attack or let an attacker write their own text into our log. Names must be string literals from
app.audit_log.ACTIONS, and keys of a details={...} literal must come from DETAIL_KEYS.

To add a name: put it in ACTIONS in app/audit_log.py and in the table in docs/DECISIONS.md.
"""

import ast
from pathlib import Path

from app.audit_log import ACTIONS, DETAIL_KEYS, FALLBACK_ACTIONS

APP = Path(__file__).resolve().parent.parent / "app"
ALLOWED = ACTIONS | FALLBACK_ACTIONS


def _call_name(node: ast.Call) -> tuple[str, str] | None:
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return func.value.id, func.attr
    return None


def findings_in(source: str, where: str = "<test>") -> list[str]:
    out = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        action_arg = details_arg = None
        if name in {("audit", "action"), ("observability", "action")}:
            action_arg = node.args[0] if node.args else None
        elif name in {("audit_log", "append"), ("audit_log", "record")}:
            keywords = {k.arg: k.value for k in node.keywords}
            action_arg, details_arg = keywords.get("action"), keywords.get("details")
        else:
            continue
        line = f"{where}:{node.lineno}"
        if not (isinstance(action_arg, ast.Constant) and isinstance(action_arg.value, str)):
            out.append(f"{line}: the action must be a string literal, not built at runtime")
        elif action_arg.value not in ALLOWED:
            out.append(f"{line}: unknown action {action_arg.value!r}; add it to ACTIONS in app/audit_log.py")
        if isinstance(details_arg, ast.Dict):
            for key in details_arg.keys:
                if not (isinstance(key, ast.Constant) and key.value in DETAIL_KEYS):
                    shown = key.value if isinstance(key, ast.Constant) else "<computed>"
                    out.append(f"{line}: details key {shown!r} is not in DETAIL_KEYS (it would be dropped)")
    return out


def test_every_action_name_in_app_is_a_known_literal():
    findings = []
    for path in sorted(APP.rglob("*.py")):
        if path.name == "audit_log.py":
            continue
        findings += findings_in(path.read_text(encoding="utf-8"), str(path.relative_to(APP.parent)))
    assert not findings, "Fix the audit calls:\n" + "\n".join(findings)


def test_the_lint_catches_what_it_should():
    bad = [
        'audit.action("tranfer.denied")',
        'audit.action("login.failed." + username)',
        'audit.action(f"login.{kind}")',
        'audit_log.append(db, action="made.up", outcome="ok")',
        'audit_log.record(action=name, outcome="ok")',
        'audit_log.append(db, action="login.ok", outcome="ok", details={"passwrd": 1})',
        'audit_log.append(db, action="login.ok", outcome="ok", details={key: 1})',
    ]
    good = [
        'audit.action("transfer.denied")',
        'audit_log.append(db, action="transfer.created", outcome="ok", details={"amount_cents": 5, "reason": "x"})',
        'audit_log.record(action="login.failed", outcome="denied", details=build())',
        'something_else.action("not ours")',
    ]
    assert all(findings_in(code) for code in bad)
    assert not any(findings_in(code) for code in good)


def test_the_documented_names_are_all_in_the_vocabulary():
    """Names the other owners already chose in docs/TASKS.md must not be rejected."""
    chosen = {
        "transfer.created", "transfer.denied", "transfer.insufficient_funds", "input.rejected",
        "login.ok", "login.failed", "login.locked", "token.invalid", "authz.denied",
        "approval.requested", "approval.granted", "approval.rejected", "approval.expired", "approval.self_denied",
        "transfer.review", "transfer.blocked", "recon.mismatch", "transfer.duplicate", "limit.exceeded",
        "transfer.reversed", "ledger.invariant_violation", "ledger.controls_disabled", "ledger.lock_timeout",
        "ledger.deadlock", "approval.mismatch",
    }
    assert chosen <= ACTIONS
