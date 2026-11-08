"""End-to-end API tests covering the happy path, validation, errors, security
headers, and the session-scoping of history."""
from __future__ import annotations

import uuid

PHISH = "http://paypal.com.secure-login.xyz/verify/account"
LEGIT = "https://www.swinburne.edu.au/"


# --- Health -----------------------------------------------------------------

def test_health_ok(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["model"] == "XGBoost"
    assert len(body["model_sha256"]) == 64


# --- Core check -------------------------------------------------------------

def test_check_phishing(client):
    r = client.post("/api/check", json={"url": PHISH})
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "phishing"
    assert 0.5 < body["malicious_probability"] <= 1.0
    assert 0.0 <= body["confidence"] <= 1.0
    assert isinstance(body["warnings"], list)
    assert isinstance(body["contributions"], list) and body["contributions"]


def test_check_legitimate(client):
    r = client.post("/api/check", json={"url": LEGIT})
    assert r.status_code == 200
    assert r.json()["verdict"] == "legitimate"


def test_check_normalises_homoglyph(client):
    # Cyrillic 'а' and 'о' in "paypal/login" should be flagged as look-alikes.
    r = client.post("/api/check", json={"url": "http://pаypal.com/lоgin"})
    assert r.status_code == 200
    assert r.json()["lookalike_characters"] is True


# --- Validation and errors --------------------------------------------------

def test_empty_url_is_422_with_friendly_message(client):
    r = client.post("/api/check", json={"url": ""})
    assert r.status_code == 422
    body = r.json()
    assert "error" in body and body["error"]["code"] == "validation_error"
    assert body["request_id"]


def test_missing_field_is_422(client):
    r = client.post("/api/check", json={})
    assert r.status_code == 422


def test_overlong_url_rejected(client):
    r = client.post("/api/check", json={"url": "http://x.com/" + "a" * 5000})
    assert r.status_code == 422


def test_unknown_path_is_json_404(client):
    r = client.get("/api/does-not-exist")
    assert r.status_code == 404
    body = r.json()
    assert body["error"]["code"] == "not_found"
    assert "request_id" in body


def test_error_response_has_no_stack_trace(client):
    r = client.post("/api/check", json={"url": ""})
    assert "Traceback" not in r.text
    assert "File \"" not in r.text


# --- Security headers --------------------------------------------------------

def test_security_headers_present(client):
    r = client.get("/api/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Request-ID"]


# --- History and session scoping --------------------------------------------

def test_history_requires_session(client):
    assert client.get("/api/history").status_code == 400


def test_history_rejects_bad_session_id(client):
    r = client.get("/api/history", headers={"X-Session-ID": "not-a-uuid"})
    assert r.status_code == 400


def test_history_is_scoped_per_session(client):
    a = {"X-Session-ID": str(uuid.uuid4())}
    b = {"X-Session-ID": str(uuid.uuid4())}
    client.post("/api/check", json={"url": PHISH}, headers=a)
    client.post("/api/check", json={"url": LEGIT}, headers=b)

    ra = client.get("/api/history", headers=a).json()
    rb = client.get("/api/history", headers=b).json()
    assert ra["count"] == 1 and rb["count"] == 1
    assert ra["items"][0]["url"] == PHISH
    assert rb["items"][0]["url"] == LEGIT


def test_history_search_is_literal_not_sql(client, session_headers):
    client.post("/api/check", json={"url": PHISH}, headers=session_headers)
    # A classic injection payload must be treated as a literal search string.
    r = client.get("/api/history", params={"search": "' OR '1'='1"}, headers=session_headers)
    assert r.status_code == 200
    assert r.json()["count"] == 0  # matched literally -> nothing


def test_clear_history(client, session_headers):
    client.post("/api/check", json={"url": PHISH}, headers=session_headers)
    r = client.delete("/api/history", headers=session_headers)
    assert r.status_code == 200 and r.json()["deleted"] == 1
    assert client.get("/api/history", headers=session_headers).json()["count"] == 0


# --- Batch ------------------------------------------------------------------

def test_batch_check(client):
    r = client.post("/api/check/batch", json={"urls": [PHISH, LEGIT]})
    assert r.status_code == 200
    body = r.json()
    assert len(body["results"]) == 2
    assert body["phishing_count"] + body["legitimate_count"] == 2


def test_batch_rejects_oversized(client):
    r = client.post("/api/check/batch", json={"urls": [LEGIT] * 100})
    assert r.status_code == 422


# --- Stats ------------------------------------------------------------------

def test_stats(client, session_headers):
    client.post("/api/check", json={"url": PHISH}, headers=session_headers)
    client.post("/api/check", json={"url": LEGIT}, headers=session_headers)
    r = client.get("/api/stats", headers=session_headers)
    assert r.status_code == 200
    assert r.json()["total"] == 2
