"""2.7 SQL injection (Intermediate/Advanced defence).

Attack
------
The history search accepts a text term and is meant to return only the caller's
own checks (scoped by their X-Session-ID). The insecure implementation builds
the SQL by pasting the search term straight into the query string:

    SELECT id FROM checks WHERE session_id = '<id>' AND url LIKE '%<search>%' ...

An attacker sends a search term that closes the string and adds its own logic,
e.g.  ' OR '1'='1  — turning the WHERE clause into something always true, so the
query returns *every* session's rows, not just the attacker's. A UNION-based
term can pull data from other columns/tables too.

Defence
-------
The real endpoint uses the ORM (`Check.url.contains(term, autoescape=True)` with
the session filter as a bound parameter). The term is sent to SQLite as a
*parameter*, never concatenated into SQL, so the same payloads are treated as a
literal string to search for and match nothing.

Measurement
-----------
We seed two separate sessions (a victim and the attacker), each with private
history, then run the attack payloads against the insecure build and the secure
build, and count how many rows belonging to *other* sessions leak back.
"""
from __future__ import annotations

import json
import urllib.parse
import urllib.request
import uuid

from _harness import running_api, rule

VICTIM_URLS = [
    "https://victim-bank-login.example/secret-account",
    "https://victim-private-note.example/payroll",
]
ATTACKER_URLS = ["https://attacker-own-check.example/harmless"]

PAYLOADS = [
    ("baseline (no injection)", "harmless"),
    ("tautology", "' OR '1'='1"),
    ("comment-out + tautology", "%' OR 1=1 -- "),
    ("union select", "%' UNION SELECT id FROM checks -- "),
]


def _req(base: str, method: str, path: str, session: str, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"{base}{path}", data=data, method=method,
        headers={"Content-Type": "application/json", "X-Session-ID": session},
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def _seed(base: str, session: str, urls: list[str]):
    for u in urls:
        _req(base, "POST", "/api/check", session, {"url": u})


def run_scenario(label: str, insecure: bool):
    env = {"PG_INSECURE_SQL_DEMO": "true" if insecure else "false"}
    with running_api(label, env) as base:
        victim = str(uuid.uuid4())
        attacker = str(uuid.uuid4())
        _seed(base, victim, VICTIM_URLS)
        _seed(base, attacker, ATTACKER_URLS)

        print(f"\n  Results for: {label}")
        print(f"    victim session seeded with {len(VICTIM_URLS)} private checks")
        print(f"    attacker session seeded with {len(ATTACKER_URLS)} of its own")
        leaked_any = False
        for name, payload in PAYLOADS:
            q = urllib.parse.quote(payload)
            try:
                resp = _req(base, "GET", f"/api/history?search={q}", attacker)
                rows = resp.get("items", [])
            except Exception as e:  # a crash is itself a finding
                print(f"    {name:26} -> ERROR {e}")
                continue
            urls = [r["url"] for r in rows]
            leaked = [u for u in urls if u in VICTIM_URLS]
            if leaked:
                leaked_any = True
            flag = "  <-- VICTIM DATA LEAKED" if leaked else ""
            print(f"    {name:26} -> {len(rows)} row(s), {len(leaked)} from victim{flag}")
        return leaked_any


def main():
    rule("2.7  SQL INJECTION  —  history search")
    print("Scenario: an attacker uses the history search box to try to read another\n"
          "session's private checks.")

    leaked_insecure = run_scenario("DEFENCE OFF (string-built SQL)", insecure=True)
    leaked_secure = run_scenario("DEFENCE ON (ORM / bound parameters)", insecure=False)

    rule("SUMMARY")
    print(f"  Insecure build leaked victim rows to the attacker: {leaked_insecure}")
    print(f"  Secure build leaked victim rows to the attacker:   {leaked_secure}")
    print("\nReading: the string-built query lets ' OR '1'='1 and UNION payloads return\n"
          "other sessions' rows. The ORM query binds the term as a parameter, so the\n"
          "exact same payloads match nothing and no cross-session data is returned.")


if __name__ == "__main__":
    main()
