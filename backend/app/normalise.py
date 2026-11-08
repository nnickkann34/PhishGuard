"""
Look-alike (homoglyph) normalisation, the defence for detection evasion.

Attack: a phisher writes "pаypal" with a Cyrillic "а" (U+0430) instead of
the Latin "a". A person reads the same word, but the model's keyword and
brand features no longer match, so the URL can slip through.

Defence: before any feature is computed, map characters that look like
Latin letters to those letters, remove invisible characters, and decode
punycode hostnames so the same trick written as "xn--..." is caught too.
The original URL is still reported, and the user is told that look-alike
characters were found, because their presence is itself suspicious.

The mapping covers the confusables most used against Latin text, taken
from the Unicode confusables data (Unicode Consortium 2024): Cyrillic,
Greek, Armenian and Latin-extended letters plus full-width and
mathematical forms, which NFKC folds automatically.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit


# Single characters that render like a Latin letter or digit.
CONFUSABLES: dict[str, str] = {
    # Cyrillic lower case
    "а": "a", "в": "b", "с": "c", "ԁ": "d", "е": "e", "һ": "h", "і": "i",
    "ј": "j", "к": "k", "ӏ": "l", "м": "m", "п": "n", "о": "o", "р": "p",
    "ԛ": "q", "г": "r", "ѕ": "s", "т": "t", "ц": "u", "ѵ": "v", "ԝ": "w",
    "х": "x", "у": "y", "ё": "e", "ї": "i", "ґ": "r",
    # Cyrillic upper case (lower-cased later, but keep the mapping explicit)
    "А": "a", "В": "b", "С": "c", "Е": "e", "Н": "h", "І": "i", "Ј": "j",
    "К": "k", "М": "m", "О": "o", "Р": "p", "Ѕ": "s", "Т": "t", "Х": "x",
    "У": "y", "Ү": "y", "Ԁ": "d", "Ԍ": "g", "Ԛ": "q", "Ԝ": "w",
    # Greek
    "α": "a", "β": "b", "ϲ": "c", "ε": "e", "η": "n", "ι": "i", "κ": "k",
    "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "γ": "y",
    "Α": "a", "Β": "b", "Ε": "e", "Ζ": "z", "Η": "h", "Ι": "i", "Κ": "k",
    "Μ": "m", "Ν": "n", "Ο": "o", "Ρ": "p", "Τ": "t", "Υ": "y", "Χ": "x",
    # Armenian
    "օ": "o", "ս": "u", "ո": "n", "ց": "g", "հ": "h", "զ": "q",
    # Latin look-alikes and IPA
    "ı": "i", "ɑ": "a", "ɡ": "g", "ʟ": "l", "ɩ": "i", "ᴅ": "d", "ᴋ": "k",
    "ⅼ": "l", "ǀ": "l", "ƚ": "l", "ɴ": "n", "ʀ": "r", "ꜱ": "s", "ᴡ": "w",
    # Digits that pass for letters in brand names
    "０": "0", "１": "1",
}

# Characters with no visible width that can hide inside a word.
INVISIBLE = {
    "​", "‌", "‍", "⁠", "﻿", "­", "᠎",
}


@dataclass
class NormalisationResult:
    original: str
    normalised: str
    homoglyphs: list[str] = field(default_factory=list)
    invisible_removed: int = 0
    punycode_decoded: bool = False

    @property
    def changed(self) -> bool:
        return self.normalised != self.original

    @property
    def suspicious(self) -> bool:
        return bool(self.homoglyphs or self.invisible_removed or self.punycode_decoded)


def _decode_punycode_host(url: str) -> tuple[str, bool]:
    """Turn xn-- labels in the hostname back into Unicode."""
    if "xn--" not in url.lower():
        return url, False
    has_scheme = "://" in url
    parts = urlsplit(url if has_scheme else "http://" + url)
    host = parts.hostname or ""
    if "xn--" not in host:
        return url, False
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except (UnicodeError, ValueError):
                pass
        labels.append(label)
    new_host = ".".join(labels)
    netloc = parts.netloc.replace(host, new_host, 1)
    rebuilt = urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    if not has_scheme:
        rebuilt = rebuilt.split("://", 1)[1]
    return rebuilt, True


def normalise_url(url: str) -> NormalisationResult:
    """Return the URL with look-alike characters mapped to Latin ones."""
    result = NormalisationResult(original=url, normalised=url)

    text, decoded = _decode_punycode_host(url)
    result.punycode_decoded = decoded

    # NFKC folds full-width, mathematical and other compatibility forms.
    text = unicodedata.normalize("NFKC", text)

    out = []
    for ch in text:
        if ch in INVISIBLE or unicodedata.category(ch) == "Cf":
            result.invisible_removed += 1
            continue
        mapped = CONFUSABLES.get(ch)
        if mapped is not None:
            result.homoglyphs.append(ch)
            out.append(mapped)
        else:
            out.append(ch)

    result.normalised = "".join(out)
    return result
