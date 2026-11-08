# PhishGuard — demo video script (target ≈ 12–13 min, hard cap 15:00)

Record in MP4. Share the screen; both team members should speak. Have the back
end and front end already running, plus a terminal in `backend/` with the venv
active for the live attack demos. Below, **[DO]** is the on-screen action and
**[SAY]** is roughly what to narrate — put it in your own words.

The brief marks: *working app*, *the two 2.7 defences shown attack-then-defence*,
*the 2.8 attack shown before/after*, and *clear explanation*. The script is built
around those.

---

## 0:00 — Intro (≈45 s)

- **[SAY]** Who you are, that this is PhishGuard: a secure web app wrapping the
  Assignment 2 phishing-URL model. One sentence on the split: React front end,
  FastAPI back end, the URL is only ever treated as text.

## 0:45 — The working app (≈2.5 min)

- **[DO]** On the home page, paste a known phishing URL
  (`http://paypal.com.secure-login.xyz/verify`). Click **Check link**.
- **[SAY]** Point out the verdict and confidence (the most prominent element),
  the meter against the 50% threshold, and the "what looks suspicious" list.
- **[DO]** Scroll to **Why this verdict?** Click a bar.
- **[SAY]** These are the model's SHAP contributions for *this* address — orange
  pushed towards phishing. Click **Show as table** to show the accessible
  alternative.
- **[DO]** Check a legitimate URL (`https://www.swinburne.edu.au/`). Show the
  green result.
- **[DO]** Check a homoglyph URL (`pаypal.com/lоgin` with Cyrillic letters —
  paste from the brief or your notes). Point out the "look-alike characters"
  warning. *(This foreshadows the 2.8 attack.)*
- **[DO]** Scroll to the session scatter chart; switch the filter to Phishing.
  Click a dot to reload that result. Show the **History** list and its search.
- **[DO]** Visit a bad URL in the address bar (e.g. `/nonsense`) to show the 404
  page, then the **How it works** page briefly.

## 3:15 — Architecture & secure design (≈2 min)

- **[DO]** Show `docs/architecture.png` (or the README diagram).
- **[SAY]** Walk the request path: CORS outermost so errors still carry it →
  request-context layer that turns any crash into a JSON 500 with a request id →
  body-size limit → security headers → Pydantic validation → InferenceGuard →
  normalise → features → model (loaded once, SHA-256 checked) → ORM → SQLite.
- **[DO]** Open `/docs`. Show the auto-generated API docs; expand `/api/check`.
- **[DO]** In dev tools Network tab, show a response's security headers (CSP,
  X-Frame-Options: DENY) and that the error body is JSON with no stack trace.

## 5:15 — Defence 1: Denial of Service (Advanced) (≈2.5 min)

- **[SAY]** The risk: `/api/check/batch` is an expensive request; a flood can
  exhaust the server. The defence: bounded thread pool + semaphore that sheds
  load with 503 instead of hanging.
- **[DO]** Run `python ../security/dos_attack.py`. While it runs, narrate the
  two phases.
- **[DO]** On the summary table, point out: defence OFF → user checks **hung**
  (8/8 failed); defence ON → latency **7 ms**, attacker load shed as 503s.

## 7:45 — Defence 2: SQL injection (Intermediate) (≈2 min)

- **[SAY]** The risk: a crafted history search could read other sessions' rows.
  The defence: parameterised ORM queries.
- **[DO]** Run `python ../security/sqli_attack.py`.
- **[DO]** Point out: insecure build → `UNION`/`OR 1=1` payloads **leak victim
  rows**; secure build → 0 rows. Same payloads, bound as parameters.

## 9:45 — Attack 2.8: Detection evasion (≈2 min)

- **[SAY]** The attack: swap Latin letters for look-alike Unicode so the model's
  learned tokens stop matching. The defence: NFKC + confusable mapping before
  feature extraction.
- **[DO]** Run `python ../security/measure_evasion.py`. Show the summary table
  and open `security/evasion_result.png`.
- **[SAY]** Up to 80% evasion with normalisation off, 0% with it on.

## 11:45 — Testing, audit, wrap-up (≈1 min)

- **[DO]** Run `python -m pytest` in `backend/` — 18 passing.
- **[DO]** Run `pip-audit -r requirements.txt` — no known vulnerabilities.
- **[SAY]** One sentence on residual risk (a classifier, not a guarantee) and
  who did what. Thank the viewer.

---

### Checklist before recording
- [ ] Back end running on :8000, front end on :5173.
- [ ] A terminal in `backend/` with the venv active for the three attack scripts.
- [ ] A homoglyph URL copied ready to paste.
- [ ] Browser zoom ~110% so text is readable in the recording.
- [ ] Watch the clock — the DoS script takes ~40 s; don't let the live demos run long.
