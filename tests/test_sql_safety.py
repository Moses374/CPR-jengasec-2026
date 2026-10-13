"""No SQL built from strings in application code (docs/DECISIONS.md, Q1 and Q3).

psycopg only refuses stacked statements ("SELECT 1; ALTER TABLE ...") when a query has
bound parameters; a string-built query without them runs every statement in it. So any
f-string, .format() or % formatting that reaches the database is a way to switch off the
ledger's triggers. Use bound parameters: text("... WHERE id = :id"), {"id": value}.
"""

import re
from pathlib import Path

APP = Path(__file__).resolve().parent.parent / "app"

PATTERNS = {
    "f-string SQL": re.compile(r"""\b(text|execute|exec_driver_sql)\(\s*[rRbB]?[fF]["']"""),
    ".format() SQL": re.compile(r"""\b(text|execute|exec_driver_sql)\(\s*["'][^"']*["']\s*\.format\("""),
    "%-formatted SQL": re.compile(r"""\b(text|execute|exec_driver_sql)\(\s*["'][^"']*["']\s*%\s*[\w(]"""),
    "concatenated SQL": re.compile(r"""\b(text|execute|exec_driver_sql)\(\s*["'][^"']*["']\s*\+"""),
    "raw driver SQL": re.compile(r"""\bexec_driver_sql\("""),
}


def test_no_string_built_sql_in_app():
    findings = []
    for path in sorted(APP.rglob("*.py")):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for name, pattern in PATTERNS.items():
                if pattern.search(line):
                    findings.append(f"{path.relative_to(APP.parent)}:{lineno}: {name}: {line.strip()}")
    assert not findings, "Use bound parameters instead:\n" + "\n".join(findings)


def test_the_guard_catches_what_it_should():
    bad = [
        'db.execute(text(f"SELECT * FROM accounts WHERE id = {account_id}"))',
        'db.execute(text("SELECT * FROM accounts WHERE id = {}".format(account_id)))',
        "db.execute(text('SELECT * FROM accounts WHERE id = %s' % account_id))",
        'db.execute(text("SELECT * FROM accounts WHERE id = " + account_id))',
        'conn.exec_driver_sql("SELECT 1")',
    ]
    good = 'db.execute(text("SELECT * FROM accounts WHERE id = :id"), {"id": account_id})'
    assert all(any(p.search(line) for p in PATTERNS.values()) for line in bad)
    assert not any(p.search(good) for p in PATTERNS.values())
