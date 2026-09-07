"""Module 4: passive URL and domain threat analysis.

Consumes URL strings extracted by Module 2 (`EmailParseResponse.urls`) and
returns explainable, rule-based indicators. Analysis uses only the URL text.

This module never connects to hosts, resolves DNS, crawls pages, or calls
external threat-intelligence APIs.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import unquote, urlsplit

from models.url_analysis import UrlAnalysisResponse, UrlAnalysisResult, UrlIndicator

MAX_URLS_PER_REQUEST = 50
MAX_URL_LENGTH = 2048
LONG_URL_THRESHOLD = 200
EXCESSIVE_SUBDOMAIN_THRESHOLD = 4
PERCENT_ENCODING_THRESHOLD = 6
HYPHEN_THRESHOLD = 4
MAX_SCORE = 100

SCORE_IP_HOSTNAME = 25
SCORE_HTTP = 10
SCORE_KEYWORD = 10
SCORE_LONG_URL = 10
SCORE_EXCESSIVE_SUBDOMAINS = 10
SCORE_PUNYCODE = 10
SCORE_AT_SIGN = 15
SCORE_NONSTANDARD_PORT = 10
SCORE_LOOKALIKE = 20
SCORE_OBFUSCATION = 5

STANDARD_WEB_PORTS = {80, 443}

SUSPICIOUS_KEYWORDS = (
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "password",
    "confirm",
    "authentication",
    "wallet",
    "payment",
)

LOOKALIKE_TERMS = ("login", "verify", "secure", "account", "support")

# Prototype list of commonly impersonated brands. Exact official hosts are not flagged.
KNOWN_BRANDS = (
    "google",
    "microsoft",
    "apple",
    "amazon",
    "paypal",
    "instagram",
    "facebook",
    "linkedin",
    "github",
    "microsoftonline",
)

_PERCENT_ENCODED = re.compile(r"%[0-9A-Fa-f]{2}")
_KEYWORD_PATTERN = re.compile(
    r"\b(?:" + "|".join(re.escape(word) for word in SUSPICIOUS_KEYWORDS) + r")\b",
    re.IGNORECASE,
)


def analyze_urls(urls: list[str]) -> UrlAnalysisResponse:
    """Analyze a list of Module 2 URL strings. Never performs network I/O."""
    results = [analyze_url(item) for item in urls]
    analyzed = sum(1 for item in results if item.parse_ok)
    overall = max((item.score for item in results), default=0)
    return UrlAnalysisResponse(
        total_urls=len(urls),
        analyzed_urls=analyzed,
        overall_score=min(overall, MAX_SCORE),
        overall_risk_level=_risk_level(overall),
        results=results,
    )


def analyze_url(raw_url: str) -> UrlAnalysisResult:
    """Analyze a single URL string using urllib.parse only."""
    original = raw_url if isinstance(raw_url, str) else str(raw_url)
    if not original or not original.strip():
        return _malformed_result(original, "URL is empty.")

    url = original.strip()
    if len(url) > MAX_URL_LENGTH:
        return _malformed_result(original, "URL exceeds the analysis length limit.")

    try:
        parts = urlsplit(url)
    except Exception:
        return _malformed_result(original, "URL could not be parsed.")

    if not parts.scheme or not parts.netloc:
        return _malformed_result(
            original,
            "URL is missing a scheme or host and could not be analyzed.",
        )

    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        return _malformed_result(
            original,
            f"Unsupported URL scheme '{parts.scheme}'. Only http and https are analyzed.",
        )

    hostname = (parts.hostname or "").lower().rstrip(".")
    if not hostname:
        return _malformed_result(original, "URL host is missing or malformed.")

    try:
        port = parts.port
    except ValueError:
        return _malformed_result(original, "URL port is malformed.")

    is_ip = _is_ip_hostname(hostname)
    subdomain_count = 0 if is_ip else _subdomain_count(hostname)
    indicators: list[UrlIndicator] = []

    if is_ip:
        indicators.append(
            UrlIndicator(
                type="ip_hostname",
                severity="high",
                message=(
                    "URL uses an IP address instead of a domain name. "
                    "This is a risk indicator, not proof that the URL is malicious."
                ),
                score=SCORE_IP_HOSTNAME,
            )
        )

    if scheme != "https":
        indicators.append(
            UrlIndicator(
                type="no_https",
                severity="medium",
                message=(
                    "URL does not use HTTPS. This is a security indicator, "
                    "not proof of phishing."
                ),
                score=SCORE_HTTP,
            )
        )

    if len(url) >= LONG_URL_THRESHOLD:
        indicators.append(
            UrlIndicator(
                type="long_url",
                severity="low",
                message=(
                    f"URL length ({len(url)} characters) exceeds {LONG_URL_THRESHOLD}. "
                    "A long URL is potentially suspicious and requires further investigation."
                ),
                score=SCORE_LONG_URL,
            )
        )

    if not is_ip and subdomain_count > EXCESSIVE_SUBDOMAIN_THRESHOLD:
        indicators.append(
            UrlIndicator(
                type="excessive_subdomains",
                severity="medium",
                message=(
                    f"Hostname has {subdomain_count} subdomain levels, which is more than "
                    f"{EXCESSIVE_SUBDOMAIN_THRESHOLD}. This is a risk indicator detected "
                    "from hostname structure."
                ),
                score=SCORE_EXCESSIVE_SUBDOMAINS,
            )
        )

    if "@" in url:
        indicators.append(
            UrlIndicator(
                type="at_sign",
                severity="high",
                message=(
                    "URL contains an '@' character. This can obfuscate the true host "
                    "and is a potentially suspicious risk indicator."
                ),
                score=SCORE_AT_SIGN,
            )
        )

    encoding_count = len(_PERCENT_ENCODED.findall(url))
    if encoding_count >= PERCENT_ENCODING_THRESHOLD:
        indicators.append(
            UrlIndicator(
                type="percent_encoding",
                severity="low",
                message=(
                    f"URL contains {encoding_count} percent-encoded sequences. "
                    "This may indicate obfuscation and requires further investigation."
                ),
                score=SCORE_OBFUSCATION,
            )
        )

    hyphen_count = hostname.count("-")
    if not is_ip and hyphen_count >= HYPHEN_THRESHOLD:
        indicators.append(
            UrlIndicator(
                type="hostname_hyphens",
                severity="low",
                message=(
                    "Hostname contains an unusual number of hyphens. "
                    "This is a conservative domain-obfuscation indicator."
                ),
                score=SCORE_OBFUSCATION,
            )
        )

    if not is_ip and _numeric_heavy(hostname):
        indicators.append(
            UrlIndicator(
                type="numeric_hostname",
                severity="low",
                message=(
                    "Hostname is numeric-heavy. This is a conservative obfuscation indicator, "
                    "not proof of malicious activity."
                ),
                score=SCORE_OBFUSCATION,
            )
        )

    if not is_ip and any(len(label) > 40 for label in hostname.split(".") if label):
        indicators.append(
            UrlIndicator(
                type="unusual_label_length",
                severity="low",
                message=(
                    "A hostname label is unusually long. This is a risk indicator detected "
                    "from hostname formatting."
                ),
                score=SCORE_OBFUSCATION,
            )
        )

    haystack = unquote(f"{parts.path or ''}?{parts.query or ''}")
    keyword_hits = sorted({match.group(0).lower() for match in _KEYWORD_PATTERN.finditer(haystack)})
    if keyword_hits:
        indicators.append(
            UrlIndicator(
                type="suspicious_keyword",
                severity="medium",
                message=(
                    "URL contains a login-related or security-related keyword "
                    f"({', '.join(keyword_hits)}). Keywords are contextual indicators, "
                    "not proof of phishing."
                ),
                score=SCORE_KEYWORD,
            )
        )

    if not is_ip and "xn--" in hostname:
        indicators.append(
            UrlIndicator(
                type="punycode",
                severity="medium",
                message=(
                    "Hostname contains punycode/IDN representation. "
                    "This is an analytical indicator, not automatic classification as malicious."
                ),
                score=SCORE_PUNYCODE,
            )
        )

    if port is not None and port not in STANDARD_WEB_PORTS:
        indicators.append(
            UrlIndicator(
                type="nonstandard_port",
                severity="medium",
                message=(
                    f"URL explicitly uses non-standard web port {port}. "
                    "No network connection was made; this is a local parsing indicator."
                ),
                score=SCORE_NONSTANDARD_PORT,
            )
        )

    lookalike = None if is_ip else _lookalike_indicator(hostname)
    if lookalike is not None:
        indicators.append(lookalike)

    score = min(sum(item.score for item in indicators), MAX_SCORE)
    return UrlAnalysisResult(
        url=original,
        scheme=scheme,
        hostname=hostname,
        port=port,
        path=parts.path or "/",
        has_query=bool(parts.query),
        has_fragment=bool(parts.fragment),
        is_ip_address=is_ip,
        uses_https=scheme == "https",
        subdomain_count=subdomain_count,
        parse_ok=True,
        indicators=indicators,
        score=score,
        risk_level=_risk_level(score),
    )


def _malformed_result(url: str, reason: str) -> UrlAnalysisResult:
    return UrlAnalysisResult(
        url=url,
        scheme=None,
        hostname=None,
        port=None,
        path=None,
        parse_ok=False,
        indicators=[
            UrlIndicator(
                type="malformed_url",
                severity="low",
                message=(
                    f"{reason} The value was not treated as a fetchable target "
                    "and no network request was made."
                ),
                score=0,
            )
        ],
        score=0,
        risk_level="low",
    )


def _risk_level(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def _is_ip_hostname(hostname: str) -> bool:
    candidate = hostname.strip("[]")
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def _subdomain_count(hostname: str) -> int:
    labels = [label for label in hostname.split(".") if label]
    if len(labels) <= 2:
        return 0
    return len(labels) - 2


def _numeric_heavy(hostname: str) -> bool:
    compact = hostname.replace(".", "").replace("-", "")
    if len(compact) < 6:
        return False
    digits = sum(char.isdigit() for char in compact)
    return digits / len(compact) >= 0.4


def _is_official_brand_host(hostname: str, brand: str) -> bool:
    roots = [f"{brand}.com"]
    if brand == "microsoftonline":
        roots.append("microsoftonline.com")
    for root in roots:
        if hostname == root or hostname.endswith(f".{root}"):
            extra_labels = hostname[: -len(root)].strip(".").split(".") if hostname != root else []
            extra_labels = [label for label in extra_labels if label]
            allowed = {"www", "mail", "login", "accounts", "account", "signin", "auth"}
            if all(label in allowed for label in extra_labels):
                return True
    return False


def _lookalike_indicator(hostname: str) -> UrlIndicator | None:
    host = hostname.lower()
    matched_brands: list[str] = []
    extra_terms: list[str] = []

    for brand in KNOWN_BRANDS:
        if not _brand_appears(host, brand):
            continue
        if _is_official_brand_host(host, brand):
            continue
        matched_brands.append(brand)

    if not matched_brands:
        return None

    token_haystack = re.split(r"[-.]", host)
    extra_terms = [term for term in LOOKALIKE_TERMS if term in token_haystack]

    if extra_terms:
        message = (
            "Hostname resembles a known brand and contains additional security-related terms "
            f"({', '.join(sorted(set(matched_brands)))}; terms: {', '.join(extra_terms)}). "
            "This is an analytical indicator and not proof that the domain is malicious."
        )
    else:
        message = (
            "Hostname resembles a known brand embedded in another domain "
            f"({', '.join(sorted(set(matched_brands)))}). "
            "This is an analytical look-alike indicator and requires further investigation."
        )

    return UrlIndicator(
        type="brand_lookalike",
        severity="high",
        message=message,
        score=SCORE_LOOKALIKE,
    )


def _brand_appears(hostname: str, brand: str) -> bool:
    if re.search(rf"(^|[-.]){re.escape(brand)}([-.]|$)", hostname):
        return True
    for label in hostname.split("."):
        if brand in label and label != brand:
            return True
    return False
