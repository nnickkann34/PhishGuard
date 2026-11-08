"""
PhishGuard
URL parsing and hostname extraction utilities.
"""

import ipaddress
import re
from urllib.parse import urlsplit


def parse_url(url):
    """
    Parse a URL without connecting to the website.

    Returns:
        parsed URL object
        hostname
        whether the original URL contained a scheme
    """

    if not isinstance(url, str):
        raise TypeError("URL must be a string")

    url = url.strip()

    if not url:
        raise ValueError("URL cannot be empty")

    has_scheme = bool(
        re.match(
            r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
            url
        )
    )

    if url.startswith("//"):
        url_to_parse = "http:" + url

    elif has_scheme:
        url_to_parse = url

    else:
        url_to_parse = "http://" + url

    try:
        parsed = urlsplit(url_to_parse)
        hostname = (parsed.hostname or "").lower()

    except ValueError as error:
        raise ValueError(
            "Invalid URL structure"
        ) from error

    if not hostname:
        raise ValueError(
            "URL does not contain a hostname"
        )

    if any(character.isspace() for character in hostname):
        raise ValueError(
            "Hostname contains whitespace"
        )

    return parsed, hostname, has_scheme


def is_ip_address(hostname):
    """
    Return 1 when the hostname is an IP address.
    Otherwise return 0.
    """

    try:
        ipaddress.ip_address(hostname)
        return 1

    except ValueError:
        return 0