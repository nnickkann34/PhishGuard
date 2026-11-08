# Security demonstrations

These scripts demonstrate the defences and the advanced attack that are marked
for section 2.7 and 2.8 of the brief. Each one runs an attack against the
running API **with the defence turned off**, then **with it turned on**, and
prints the measurements that go into the report.

They talk to the API over HTTP, exactly as an external attacker would — none of
them import the application's own code to "cheat".

| Script | Brief section | What it shows |
| --- | --- | --- |
| `dos_attack.py` | 2.7 — Denial of Service (Advanced) | A flood of expensive batch requests freezes the undefended server; with admission control it stays responsive and sheds load with `503`. |
| `sqli_attack.py` | 2.7 — SQL injection (Intermediate) | A crafted history search leaks other sessions' rows from the insecure query; the ORM query returns nothing extra. |
| `measure_evasion.py` | 2.8 — Detection evasion (homoglyph) | Phishing URLs are rewritten with look-alike Unicode characters. Evasion rate is measured with normalisation off vs on. |

## Running

Start the API first (see the project README). Then, from the repository root:

```bash
python security/dos_attack.py
python security/sqli_attack.py
python security/measure_evasion.py
```

Each script starts the API itself in the two required configurations (it sets
the relevant `PG_*` environment variables and launches `uvicorn` on a spare
port), so you do not need to restart anything by hand. The toggles exist **only
to demonstrate the before/after** — in normal operation every defence is on and
every demo flag is off, which is the default in `config.py`.

## The toggles

| Env var | Default (secure) | Insecure demo value |
| --- | --- | --- |
| `PG_DOS_PROTECTION` | `true` | `false` |
| `PG_INSECURE_SQL_DEMO` | `false` | `true` |
| `PG_NORMALISE_HOMOGLYPHS` | `true` | `false` |

Nothing reads these from user input; they are server-side configuration, read
once at start-up.
