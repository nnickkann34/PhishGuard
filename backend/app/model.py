"""
Model loading and prediction.

The model is an XGBoost classifier trained in Assignment 2. It is stored
in XGBoost's own JSON format rather than as a joblib/pickle file: loading
JSON cannot execute code, whereas unpickling a tampered file can. Its
SHA-256 hash is also checked at start-up, so a swapped file is refused.

Prediction reuses the exact feature code from training
(app/features/lexical_features.py), so the model sees the same 26
features, computed the same way, as it did when it was trained.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import xgboost as xgb

from app.features.extract_domains import parse_url
from app.features.lexical_features import EXTRACTOR, canonical_url, extract_url_features
from app.normalise import NormalisationResult, normalise_url


class ModelIntegrityError(RuntimeError):
    """The model file on disk does not match its expected hash."""


# Plain-English names for the features, shown to users.
FEATURE_LABELS: dict[str, str] = {
    "url_length": "Address length",
    "hostname_length": "Domain name length",
    "path_length": "Path length",
    "query_length": "Query string length",
    "dot_count": "Number of dots",
    "hyphen_count": "Number of hyphens",
    "underscore_count": "Number of underscores",
    "slash_count": "Number of slashes",
    "at_count": "'@' symbols",
    "question_count": "'?' symbols",
    "equals_count": "'=' symbols",
    "percent_count": "Percent-encoded characters",
    "digit_count": "Number of digits",
    "digit_ratio": "Share of digits",
    "special_character_ratio": "Share of special characters",
    "subdomain_depth": "Subdomain levels",
    "query_parameter_count": "Query parameters",
    "has_ip_address": "IP address instead of a domain",
    "has_punycode": "Punycode (encoded international) domain",
    "suspicious_word_count": "Suspicious words (login, verify, ...)",
    "suspicious_tld": "Suspicious top-level domain",
    "uses_shortener": "Link-shortening service",
    "hosted_on_free_platform": "Free website-builder hosting",
    "brand_impersonation": "Brand name outside its own domain",
    "hostname_entropy": "Randomness of the domain name",
    "url_entropy": "Randomness of the address",
}


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass
class Prediction:
    url: str
    analysed_url: str
    verdict: str
    malicious_probability: float
    confidence: float
    contributions: list[dict]
    warnings: list[str]
    normalisation: NormalisationResult | None


class PhishingModel:
    """Loaded once at start-up and shared by every request."""

    def __init__(self, model_path: Path, metadata_path: Path, sha256_path: Path):
        expected = sha256_path.read_text(encoding="utf-8").split()[0].strip().lower()
        actual = sha256_of(model_path)
        if actual != expected:
            raise ModelIntegrityError(
                f"Model hash mismatch for {model_path.name}: refusing to load."
            )

        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        self.feature_columns: list[str] = metadata["feature_columns"]
        self.threshold: float = float(metadata["decision_threshold"])
        self.name: str = metadata["model_name"]
        self.training_rows: int = metadata["training_rows"]
        self.sha256 = actual

        self.booster = xgb.Booster()
        self.booster.load_model(str(model_path))
        # Inference must not spawn its own thread pool per call; the
        # server's worker pool controls concurrency instead.
        self.booster.set_param({"nthread": 1})

    def _features(self, url: str) -> np.ndarray:
        feats = extract_url_features(url)
        return np.array([[float(feats[c]) for c in self.feature_columns]], dtype=np.float32)

    def predict(self, url: str, normalise: bool = True) -> Prediction:
        norm = normalise_url(url) if normalise else None
        analysed = norm.normalised if norm else url

        # Raises ValueError for addresses with no usable hostname.
        parse_url(canonical_url(analysed))

        x = self._features(analysed)
        dmat = xgb.DMatrix(x, feature_names=self.feature_columns)
        prob = float(self.booster.predict(dmat)[0])

        # Per-feature contributions (SHAP values, in log-odds) explain
        # which parts of the address pushed the score up or down.
        contribs = self.booster.predict(dmat, pred_contribs=True)[0]
        contributions = []
        for name, value, contrib in zip(self.feature_columns, x[0], contribs[:-1]):
            contributions.append({
                "feature": name,
                "label": FEATURE_LABELS.get(name, name),
                "value": round(float(value), 4),
                "contribution": round(float(contrib), 4),
            })
        contributions.sort(key=lambda c: abs(c["contribution"]), reverse=True)

        verdict = "phishing" if prob >= self.threshold else "legitimate"
        confidence = prob if verdict == "phishing" else 1 - prob

        return Prediction(
            url=url,
            analysed_url=analysed,
            verdict=verdict,
            malicious_probability=round(prob, 4),
            confidence=round(confidence, 4),
            contributions=contributions,
            warnings=self._warnings(analysed, x[0], norm),
            normalisation=norm,
        )

    def _warnings(self, url: str, x: np.ndarray, norm: NormalisationResult | None) -> list[str]:
        """Human-readable notes on the parts of the address that look risky."""
        f = dict(zip(self.feature_columns, x))
        notes = []
        if norm and norm.homoglyphs:
            shown = "".join(sorted(set(norm.homoglyphs)))
            notes.append(f"Contains look-alike characters ({shown}) that imitate Latin letters.")
        if norm and norm.invisible_removed:
            notes.append("Contains invisible characters hidden inside the address.")
        if norm and norm.punycode_decoded or f["has_punycode"]:
            notes.append("Uses an encoded international (punycode) domain name.")
        if f["has_ip_address"]:
            notes.append("Uses an IP address instead of a domain name.")
        if f["at_count"]:
            notes.append("Contains '@', which can hide the real destination.")
        if f["brand_impersonation"]:
            notes.append("Mentions a well-known brand outside that brand's own domain.")
        if f["hosted_on_free_platform"]:
            notes.append("Hosted on a free website builder, popular for throwaway pages.")
        if f["uses_shortener"]:
            notes.append("Uses a link shortener, which hides the real destination.")
        if f["suspicious_tld"]:
            suffix = EXTRACTOR(canonical_url(url).split("/")[0]).suffix
            notes.append(f"Uses a top-level domain often seen in phishing (.{suffix}).")
        if f["subdomain_depth"] >= 3:
            notes.append(f"Has {int(f['subdomain_depth'])} levels of subdomains.")
        if f["url_length"] >= 100:
            notes.append(f"Unusually long address ({int(f['url_length'])} characters).")
        if f["suspicious_word_count"]:
            notes.append("Contains words common in phishing, such as 'login' or 'verify'.")
        return notes
