"""
CivicShield — URL Extractor
Finds all URLs in a block of text.

Strategy:
  1. Standard http/https/ftp URL regex
  2. Bare domain heuristic (parivahan.gov.in without scheme)
  3. De-duplicate, preserve order of first appearance
"""

import re
from typing import Optional


# RFC-3986 URL pattern restricted to http/https
_URL_PATTERN = re.compile(
    r"""(?:
        https?://                           # scheme
        (?:[^\s/$.?#].[^\s]*)               # authority + path
    )""",
    re.VERBOSE | re.IGNORECASE,
)

# Heuristic: bare domain references for official government portals
_BARE_DOMAIN_PATTERN = re.compile(
    r"""(?<![\w@/.-])
        (?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*
        (?:parivahan\.gov\.in|echallan\.parivahan\.gov\.in|transport\.gov\.in|morth\.nic\.in|nic\.in|gov\.in)
        (?::\d+)?
        (?:/[^\s<>'")\]]*)?
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Common URL-shortener pattern in WhatsApp messages: "Link: <url>"
_LINK_LABEL_PATTERN = re.compile(
    r"(?:link|url|visit|click|open)\s*:\s*(https?://\S+)",
    re.IGNORECASE,
)

_TRAILING_PUNCTUATION = ".,;:)'\"!?]>"


def extract_urls(text: str) -> list[str]:
    """
    Extract all URLs from a text string.
    Returns a deduplicated list preserving first-appearance order.

    Note: This is a best-effort extractor for SMS/WhatsApp/email text.
    URL detection in natural-language text is inherently imperfect.
    """
    if not text:
        return []

    seen: set[str] = set()
    results: list[str] = []

    def _add(url: str) -> None:
        url = url.strip().rstrip(_TRAILING_PUNCTUATION)
        if url and url not in seen:
            seen.add(url)
            results.append(url)

    # Match standard URLs
    for m in _URL_PATTERN.finditer(text):
        _add(m.group(0))

    # Match bare gov.in domains (add https:// scheme for downstream processing)
    for m in _BARE_DOMAIN_PATTERN.finditer(text):
        bare = m.group(0).strip().rstrip(_TRAILING_PUNCTUATION)
        if bare:
            full = f"https://{bare}"
            if full not in seen and bare not in seen:
                _add(full)

    # Match link labels
    for m in _LINK_LABEL_PATTERN.finditer(text):
        _add(m.group(1))

    return results


def normalize_url(url: str) -> str:
    """
    Basic URL normalization: lowercase scheme and host, strip trailing slash.
    Does NOT fetch or resolve the URL.
    """
    url = url.strip()
    # Lowercase scheme and host
    if "://" in url:
        scheme, rest = url.split("://", 1)
        if "/" in rest:
            host, path = rest.split("/", 1)
            url = f"{scheme.lower()}://{host.lower()}/{path}"
        else:
            url = f"{scheme.lower()}://{rest.lower()}"
    return url
