"""Request and response models. Pydantic validates every request against these."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.config import get_settings

_settings = get_settings()


def _clean_url(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("Enter a web address.")
    if any(ch in value for ch in (" ", "\t", "\n", "\r")):
        raise ValueError("A web address cannot contain spaces or line breaks.")
    if "." not in value and ":" not in value:
        raise ValueError("That does not look like a web address (no domain found).")
    return value


class CheckRequest(BaseModel):
    model_config = ConfigDict(json_schema_extra={
        "examples": [{"url": "http://paypal.com.secure-login.xyz/verify"}]
    })

    url: str = Field(
        ...,
        max_length=_settings.max_url_length,
        description="The web address to check. It is analysed as text only and never visited.",
    )

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        return _clean_url(v)


class BatchCheckRequest(BaseModel):
    model_config = ConfigDict(json_schema_extra={
        "examples": [{"urls": ["https://www.swinburne.edu.au", "bit.ly/3xYz-login"]}]
    })

    urls: list[str] = Field(
        ...,
        min_length=1,
        max_length=_settings.max_batch_urls,
        description=f"Up to {_settings.max_batch_urls} web addresses, for example every link in one email.",
    )

    @field_validator("urls")
    @classmethod
    def validate_urls(cls, v: list[str]) -> list[str]:
        cleaned = []
        for i, item in enumerate(v):
            if len(item) > _settings.max_url_length:
                raise ValueError(f"Address {i + 1} is longer than {_settings.max_url_length} characters.")
            try:
                cleaned.append(_clean_url(item))
            except ValueError as exc:
                raise ValueError(f"Address {i + 1}: {exc}") from None
        return cleaned


class Contribution(BaseModel):
    feature: str = Field(description="Internal feature name.")
    label: str = Field(description="Plain-English feature name.")
    value: float = Field(description="The feature's value for this address.")
    contribution: float = Field(
        description="How much this feature pushed the score towards phishing (positive) "
                    "or legitimate (negative), in log-odds."
    )


class CheckResult(BaseModel):
    model_config = ConfigDict(json_schema_extra={"examples": [{
        "id": 42,
        "url": "http://paypal.com.secure-login.xyz/verify",
        "verdict": "phishing",
        "confidence": 0.97,
        "malicious_probability": 0.97,
        "warnings": ["Mentions a well-known brand outside that brand's own domain."],
        "lookalike_characters": False,
        "contributions": [{"feature": "brand_impersonation", "label": "Brand name outside its own domain",
                           "value": 1.0, "contribution": 2.1}],
        "checked_at": "2026-11-08T08:00:00Z",
    }]})

    id: int | None = Field(None, description="History record id (absent for batch items).")
    url: str = Field(description="The address exactly as submitted.")
    verdict: Literal["phishing", "legitimate"]
    confidence: float = Field(ge=0, le=1, description="Model confidence in the verdict (0-1).")
    malicious_probability: float = Field(ge=0, le=1, description="Probability the address is phishing.")
    warnings: list[str] = Field(description="Parts of the address that look suspicious.")
    lookalike_characters: bool = Field(description="True if look-alike Unicode characters were found and normalised.")
    contributions: list[Contribution] = Field(description="Top features behind the verdict, largest first.")
    checked_at: datetime


class BatchCheckResult(BaseModel):
    results: list[CheckResult]
    phishing_count: int
    legitimate_count: int


class HistoryItem(BaseModel):
    id: int
    url: str
    verdict: Literal["phishing", "legitimate"]
    confidence: float
    malicious_probability: float
    warnings: list[str]
    checked_at: datetime


class HistoryResponse(BaseModel):
    items: list[HistoryItem]
    count: int


class StatsResponse(BaseModel):
    total: int
    counts: dict[str, int]
    average_confidence: dict[str, float | None]


class ClearResponse(BaseModel):
    deleted: int


class HealthResponse(BaseModel):
    status: Literal["ok"]
    model: str
    model_sha256: str
    dos_protection: bool
    homoglyph_normalisation: bool


class ErrorBody(BaseModel):
    code: str = Field(description="Stable machine-readable error code.")
    message: str = Field(description="Human-readable explanation.")
    details: list[dict] | None = Field(None, description="Per-field problems, for validation errors.")


class ErrorResponse(BaseModel):
    model_config = ConfigDict(json_schema_extra={"examples": [{
        "error": {"code": "validation_error", "message": "The request is not valid.",
                  "details": [{"field": "url", "problem": "Enter a web address."}]},
        "request_id": "3f2b9c1e",
    }]})

    error: ErrorBody
    request_id: str
