"""
PhishGuard
Lexical feature extraction for URL strings.
"""

import math
import re
from collections import Counter

import tldextract

from app.features.extract_domains import (
    parse_url,
    is_ip_address
)


EXTRACTOR = tldextract.TLDExtract(
    suffix_list_urls=()
)


SUSPICIOUS_WORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "password",
    "confirm",
    "bank",
    "paypal",
    "wallet"
]


SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "click",
    "link",
    "work",
    "support",
    "info"
}


# Link-shortening services hide the real destination of a link.
# "Uses a URL shortening service" is one of the standard phishing
# URL indicators (Mohammad, Thabtah & McCluskey 2014).
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "rb.gy", "cutt.ly", "shorturl.at", "rebrand.ly",
    "tiny.cc", "s.id", "t.ly", "bl.ink", "lnkd.in", "tr.ee",
    "rebrandly.com", "shorte.st", "adf.ly",
}

# Free website builders and hosting platforms give attackers a
# disposable subdomain on a trusted parent domain at no cost. Our
# phishing-only clustering found a large group of this kind on the
# training data (e.g. *.web.app, *.godaddysites.com, *.glitch.me).
FREE_HOSTING_DOMAINS = {
    "000webhostapp.com", "weebly.com", "weeblysite.com", "wixsite.com",
    "blogspot.com", "wordpress.com", "firebaseapp.com", "web.app",
    "glitch.me", "github.io", "pages.dev", "netlify.app", "vercel.app",
    "herokuapp.com", "godaddysites.com", "yolasite.com", "webnode.com",
    "webnode.es", "webnode.page", "dweb.link", "repl.co", "duckdns.org",
    "ngrok.io", "azurewebsites.net", "appspot.com", "square.site",
    "my-free.website", "backblazeb2.com", "r2.dev", "workers.dev",
    "framer.app", "carrd.co", "jimdosite.com", "sites.google.com",
    "myshopify.com", "webflow.io", "gitbook.io", "notion.site",
}

# Brands most often impersonated in phishing (APWG 2023 reports).
# A brand name that appears in the subdomain or path, while the
# registered domain belongs to someone else, is a classic
# impersonation pattern (e.g. paypal.com.secure-login.xyz).
TARGET_BRANDS = [
    "paypal", "apple", "icloud", "microsoft", "office365", "outlook",
    "onedrive", "google", "gmail", "amazon", "netflix", "facebook",
    "instagram", "whatsapp", "linkedin", "dropbox", "docusign",
    "adobe", "ebay", "chase", "wellsfargo", "bankofamerica", "hsbc",
    "americanexpress", "dhl", "fedex", "usps", "auspost", "metamask",
    "coinbase", "binance", "steam", "yahoo", "battle.net", "walmart",
]


def entropy(text):
    """
    Calculate Shannon character entropy.
    """

    if not text:
        return 0.0

    frequencies = Counter(text)

    length = len(text)

    return -sum(
        (count / length)
        * math.log2(count / length)
        for count in frequencies.values()
    )


SCHEME_PATTERN = re.compile(
    r"^[a-zA-Z][a-zA-Z0-9+.-]*://"
)

WWW_PATTERN = re.compile(
    r"^www\d*\.",
    re.IGNORECASE
)


def canonical_url(url):
    """
    Put a URL into one standard written form before
    features are extracted.

    The training sources write the same kind of address
    differently: Kaggle benign URLs rarely include
    "http://", PhiUSIIL benign URLs are always written as
    "https://www.<domain>", and PhishBench benign URLs are
    "https://<domain>". Without this step the model learns
    how each dataset formats its URLs instead of what makes
    a URL malicious, and it fails on new data (52% accuracy
    on the PhishBench holdout).

    The scheme, a leading "www." and a trailing "/" are
    removed. They do not change which site a URL points to.
    """

    text = str(url).strip()

    text = SCHEME_PATTERN.sub("", text)

    if text.startswith("//"):
        text = text[2:]

    text = WWW_PATTERN.sub("", text)

    stripped = text.rstrip("/")

    return stripped or text


def extract_url_features(url):
    """
    Convert a raw URL into numeric features.

    Features are computed on the canonical form of the URL
    (see canonical_url), so how a dataset happened to write
    the scheme or "www." cannot influence the prediction.
    """

    original_url = canonical_url(url)

    parsed, hostname, has_scheme = parse_url(
        original_url
    )

    extracted = EXTRACTOR(hostname)

    subdomain = extracted.subdomain or ""

    suffix = extracted.suffix or ""

    lower_url = original_url.lower()

    digits = sum(
        character.isdigit()
        for character in original_url
    )

    special_characters = sum(
        not character.isalnum()
        for character in original_url
    )

    subdomain_depth = (
        len(
            [
                part
                for part in subdomain.split(".")
                if part
            ]
        )
    )

    query_parameters = (
        len(parsed.query.split("&"))
        if parsed.query
        else 0
    )

    registered_domain = (
        extracted.top_domain_under_public_suffix
        or hostname
    ).lower()

    rest_of_url = (
        subdomain
        + " "
        + parsed.path
        + " "
        + parsed.query
    ).lower()

    brand_impersonation = int(
        any(
            brand in rest_of_url
            and brand.split(".")[0]
            not in registered_domain
            for brand in TARGET_BRANDS
        )
    )

    hosted_on_free_platform = int(
        any(
            hostname == platform
            or hostname.endswith("." + platform)
            for platform in FREE_HOSTING_DOMAINS
        )
    )

    suspicious_word_count = sum(
        word in lower_url
        for word in SUSPICIOUS_WORDS
    )

    return {
        "url_length":
            len(original_url),

        "hostname_length":
            len(hostname),

        "path_length":
            len(parsed.path),

        "query_length":
            len(parsed.query),

        "dot_count":
            original_url.count("."),

        "hyphen_count":
            original_url.count("-"),

        "underscore_count":
            original_url.count("_"),

        "slash_count":
            original_url.count("/"),

        "at_count":
            original_url.count("@"),

        "question_count":
            original_url.count("?"),

        "equals_count":
            original_url.count("="),

        "percent_count":
            original_url.count("%"),

        "digit_count":
            digits,

        "digit_ratio":
            digits / max(
                len(original_url),
                1
            ),

        "special_character_ratio":
            special_characters / max(
                len(original_url),
                1
            ),

        "subdomain_depth":
            subdomain_depth,

        "query_parameter_count":
            query_parameters,

        "has_ip_address":
            is_ip_address(hostname),

        "has_punycode":
            int(
                "xn--" in hostname
            ),

        "suspicious_word_count":
            suspicious_word_count,

        "suspicious_tld":
            int(
                suffix.lower()
                in SUSPICIOUS_TLDS
            ),

        "uses_shortener":
            int(
                registered_domain
                in SHORTENER_DOMAINS
            ),

        "hosted_on_free_platform":
            hosted_on_free_platform,

        "brand_impersonation":
            brand_impersonation,

        "hostname_entropy":
            entropy(hostname),

        "url_entropy":
            entropy(original_url)
    }