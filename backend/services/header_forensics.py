"""Module 3: rule-based email header forensics.

Consumes the structured headers produced by Module 2 (`EmailHeaders`) and
returns explainable forensic findings. This is not an AI/ML threat model.
An IP or domain mismatch is an observed indicator, not proof of an attacker.
"""

from __future__ import annotations

import ipaddress
import re
from email.utils import parseaddr

from models.email import EmailHeaders, EmailParseResponse
from models.forensics import (
    AuthenticationAnalysis,
    ForensicIndicator,
    ForensicSummary,
    HeaderForensicsResponse,
    ObservedIP,
    ReceivedHop,
    SenderAnalysis,
)

_IPV4 = re.compile(
    r"(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
)
_IPV6_BRACKET = re.compile(r"\[(?:IPv6:)?([0-9a-fA-F:]+)\]", re.IGNORECASE)
_EMAIL_IN_TEXT = re.compile(r"[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}", re.IGNORECASE)
_MESSAGE_ID_DOMAIN = re.compile(r"@([^>\s]+)")

_SPF_VALUES = {
    "pass",
    "fail",
    "softfail",
    "neutral",
    "none",
    "temperror",
    "permerror",
    "unknown",
}
_DKIM_VALUES = {"pass", "fail", "none", "unknown"}
_DMARC_VALUES = {"pass", "fail", "none", "unknown"}

# Lower rank = more severe when combining multiple authentication headers.
_SPF_RANK = {
    "fail": 0,
    "permerror": 1,
    "temperror": 2,
    "softfail": 3,
    "neutral": 4,
    "none": 5,
    "unknown": 6,
    "pass": 7,
}
_DKIM_RANK = {"fail": 0, "none": 1, "unknown": 2, "pass": 3}
_DMARC_RANK = {"fail": 0, "none": 1, "unknown": 2, "pass": 3}

_SPF_TOKEN = re.compile(r"\bspf\s*=\s*([a-z]+)", re.IGNORECASE)
_DKIM_TOKEN = re.compile(r"\bdkim\s*=\s*([a-z]+)", re.IGNORECASE)
_DMARC_TOKEN = re.compile(r"\bdmarc\s*=\s*([a-z]+)", re.IGNORECASE)
_RECEIVED_SPF_LEAD = re.compile(
    r"^\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b",
    re.IGNORECASE,
)

# Explainable, isolated scoring table. Easy to tune without touching parsing.
_SCORE_SPF_FAIL = 25
_SCORE_SPF_SOFTFAIL = 12
_SCORE_SPF_PERMERROR = 10
_SCORE_DKIM_FAIL = 20
_SCORE_DMARC_FAIL = 25
_SCORE_FROM_REPLY_TO_MISMATCH = 15
_SCORE_FROM_RETURN_PATH_MISMATCH = 15
_SCORE_FROM_MESSAGE_ID_MISMATCH = 10
_SCORE_MISSING_FROM = 12
_SCORE_MALFORMED_ADDRESS = 8
_SCORE_MALFORMED_RECEIVED = 6
_SCORE_MISSING_MESSAGE_ID = 4
_MAX_SCORE = 100


def analyze_parsed_email(parsed: EmailParseResponse) -> HeaderForensicsResponse:
    """Run Module 3 against a full Module 2 parse result."""
    return analyze_headers(parsed.headers)


def analyze_headers(headers: EmailHeaders) -> HeaderForensicsResponse:
    indicators: list[ForensicIndicator] = []
    findings: list[str] = []
    observed_evidence: list[str] = []
    score_breakdown: list[str] = []
    score = 0

    sender = _analyze_sender(headers, indicators, findings, observed_evidence)
    authentication = _analyze_authentication(
        headers, indicators, findings, observed_evidence
    )
    received_chain = _analyze_received_chain(
        headers, indicators, findings, observed_evidence
    )

    score += _apply_auth_scores(authentication, score_breakdown, findings)
    score += _apply_sender_scores(sender, headers, score_breakdown, findings)
    score += _apply_header_quality_scores(
        headers, received_chain, score_breakdown, findings, indicators
    )
    score = min(score, _MAX_SCORE)

    risk_level = _risk_level(score)
    confidence = _confidence(headers, authentication, received_chain)

    if not findings:
        findings.append(
            "No high-confidence forensic indicators were produced from the available headers."
        )

    findings.append(
        "This score is a simple rule-based header forensic assessment, not a final AI/ML threat decision."
    )

    return HeaderForensicsResponse(
        summary=ForensicSummary(
            risk_level=risk_level,
            score=score,
            confidence=confidence,
            max_score=_MAX_SCORE,
        ),
        sender_analysis=sender,
        authentication=authentication,
        received_chain=received_chain,
        indicators=indicators,
        findings=findings,
        observed_evidence=observed_evidence,
        score_breakdown=score_breakdown,
    )


def _analyze_sender(
    headers: EmailHeaders,
    indicators: list[ForensicIndicator],
    findings: list[str],
    observed_evidence: list[str],
) -> SenderAnalysis:
    from_raw = headers.from_address
    reply_to_raw = headers.reply_to
    return_path_raw = headers.return_path
    message_id_raw = headers.message_id

    from_addr, from_domain, from_malformed = _parse_mailbox(from_raw)
    reply_addr, reply_domain, reply_malformed = _parse_mailbox(reply_to_raw)
    return_addr, return_domain, return_malformed = _parse_mailbox(return_path_raw)
    message_id_domain = _message_id_domain(message_id_raw)

    sender_findings: list[str] = []

    if from_raw:
        observed_evidence.append(f"From: {from_raw}")
    if reply_to_raw:
        observed_evidence.append(f"Reply-To: {reply_to_raw}")
    if return_path_raw:
        observed_evidence.append(f"Return-Path: {return_path_raw}")
    if message_id_raw:
        observed_evidence.append(f"Message-ID: {message_id_raw}")

    for label, raw, malformed in (
        ("From", from_raw, from_malformed),
        ("Reply-To", reply_to_raw, reply_malformed),
        ("Return-Path", return_path_raw, return_malformed),
    ):
        if raw and malformed:
            indicators.append(
                ForensicIndicator(
                    type="malformed_address",
                    severity="medium",
                    description=f"{label} could not be parsed as a well-formed mailbox address.",
                    evidence=raw,
                    confidence="analytical_finding",
                )
            )
            sender_findings.append(f"Malformed {label} value observed.")

    if from_domain and reply_domain and not _domains_consistent(from_domain, reply_domain):
        desc = (
            "From and Reply-To domains differ. This is a forensic indicator of "
            "possible reply diversion, not proof of phishing."
        )
        indicators.append(
            ForensicIndicator(
                type="from_reply_to_domain_mismatch",
                severity="medium",
                description=desc,
                evidence=f"from_domain={from_domain}; reply_to_domain={reply_domain}",
            )
        )
        sender_findings.append(desc)
        findings.append(desc)

    if from_domain and return_domain and not _domains_consistent(from_domain, return_domain):
        desc = (
            "From and Return-Path domains differ. Bounce handling may not match the "
            "visible sender; treat as an indicator, not proof of malice."
        )
        indicators.append(
            ForensicIndicator(
                type="from_return_path_domain_mismatch",
                severity="medium",
                description=desc,
                evidence=f"from_domain={from_domain}; return_path_domain={return_domain}",
            )
        )
        sender_findings.append(desc)
        findings.append(desc)

    if from_domain and message_id_domain and not _domains_consistent(
        from_domain, message_id_domain
    ):
        desc = (
            "Message-ID domain does not match the From domain. This can occur with "
            "legitimate mailing systems and is only a forensic indicator."
        )
        indicators.append(
            ForensicIndicator(
                type="from_message_id_domain_mismatch",
                severity="low",
                description=desc,
                evidence=f"from_domain={from_domain}; message_id_domain={message_id_domain}",
            )
        )
        sender_findings.append(desc)
        findings.append(desc)

    if not from_raw:
        sender_findings.append("From header is missing.")

    return SenderAnalysis(
        from_address=from_addr or from_raw,
        from_domain=from_domain,
        reply_to=reply_addr or reply_to_raw,
        reply_to_domain=reply_domain,
        return_path=return_addr or return_path_raw,
        return_path_domain=return_domain,
        message_id=message_id_raw,
        message_id_domain=message_id_domain,
        findings=sender_findings,
    )


def _analyze_authentication(
    headers: EmailHeaders,
    indicators: list[ForensicIndicator],
    findings: list[str],
    observed_evidence: list[str],
) -> AuthenticationAnalysis:
    spf_results: list[str] = []
    dkim_results: list[str] = []
    dmarc_results: list[str] = []

    for raw in headers.authentication_results:
        observed_evidence.append(f"Authentication-Results: {raw}")
        spf_results.extend(_tokens(_SPF_TOKEN, raw, _SPF_VALUES))
        dkim_results.extend(_tokens(_DKIM_TOKEN, raw, _DKIM_VALUES))
        dmarc_results.extend(_tokens(_DMARC_TOKEN, raw, _DMARC_VALUES))

    for raw in headers.received_spf:
        observed_evidence.append(f"Received-SPF: {raw}")
        lead = _RECEIVED_SPF_LEAD.match(raw or "")
        if lead:
            value = lead.group(1).lower()
            if value in _SPF_VALUES:
                spf_results.append(value)
        spf_results.extend(_tokens(_SPF_TOKEN, raw, _SPF_VALUES))

    dkim_present = bool(headers.dkim_signature)
    if dkim_present:
        for raw in headers.dkim_signature:
            observed_evidence.append("DKIM-Signature present (result not inferred from signature bytes).")
            if raw:
                observed_evidence.append(f"DKIM-Signature: {raw[:180]}")

    spf = _worst(spf_results, _SPF_RANK, "unknown")
    dkim = _worst(dkim_results, _DKIM_RANK, "unknown")
    dmarc = _worst(dmarc_results, _DMARC_RANK, "unknown")

    if dkim == "unknown" and not headers.authentication_results and not dkim_present:
        dkim = "unknown"
    if not headers.authentication_results and not headers.received_spf:
        if spf == "unknown":
            findings.append(
                "No Authentication-Results or Received-SPF header was available; SPF is unknown."
            )
        if dmarc == "unknown":
            findings.append(
                "No Authentication-Results header was available; DMARC is unknown."
            )
        if dkim == "unknown":
            findings.append(
                "No DKIM authentication result was available; DKIM is unknown."
            )

    if dkim_present and dkim == "unknown":
        findings.append(
            "A DKIM-Signature header was observed, but no Authentication-Results DKIM verdict was present, so the result is left unknown."
        )

    if spf == "fail":
        indicators.append(
            ForensicIndicator(
                type="spf_fail",
                severity="high",
                description="SPF evaluation failed for this message path.",
                evidence=_auth_evidence(headers, "spf"),
            )
        )
        findings.append("SPF failure is a forensic indicator of sender-path inconsistency.")
    elif spf == "softfail":
        indicators.append(
            ForensicIndicator(
                type="spf_softfail",
                severity="medium",
                description="SPF returned softfail.",
                evidence=_auth_evidence(headers, "spf"),
            )
        )

    if dkim == "fail":
        indicators.append(
            ForensicIndicator(
                type="dkim_fail",
                severity="high",
                description="DKIM evaluation failed.",
                evidence=_auth_evidence(headers, "dkim"),
            )
        )
        findings.append("DKIM failure is a forensic indicator that the signature did not validate.")

    if dmarc == "fail":
        indicators.append(
            ForensicIndicator(
                type="dmarc_fail",
                severity="high",
                description="DMARC evaluation failed.",
                evidence=_auth_evidence(headers, "dmarc"),
            )
        )
        findings.append("DMARC failure is a forensic indicator of alignment or authentication issues.")

    return AuthenticationAnalysis(
        spf=spf,
        dkim=dkim,
        dmarc=dmarc,
        authentication_results=list(headers.authentication_results),
        received_spf=list(headers.received_spf),
        dkim_signature_present=dkim_present,
    )


def _analyze_received_chain(
    headers: EmailHeaders,
    indicators: list[ForensicIndicator],
    findings: list[str],
    observed_evidence: list[str],
) -> list[ReceivedHop]:
    hops: list[ReceivedHop] = []
    received = list(headers.received or [])

    if not received:
        findings.append(
            "No Received headers were present, so hop-path analysis could not be performed."
        )
        return hops

    last_index = len(received) - 1
    for index, raw in enumerate(received):
        try:
            observed_ips = _extract_observed_ips(raw)
            notes: list[str] = []
            position = None
            if index == 0:
                position = "most_recent"
                notes.append(
                    "First listed Received header is typically the most recent hop (closest to the receiving system)."
                )
            if index == last_index:
                position = "earliest_observed" if position is None else "most_recent_and_only"
                notes.append(
                    "Last listed Received header is typically the earliest observed hop and may describe probable source infrastructure, not a confirmed attacker location."
                )

            if not re.search(r"\bfrom\b", raw, re.IGNORECASE) and not re.search(
                r"\bby\b", raw, re.IGNORECASE
            ):
                notes.append("Received header does not contain typical from/by tokens.")
                indicators.append(
                    ForensicIndicator(
                        type="malformed_received_header",
                        severity="low",
                        description="A Received header is missing typical from/by structure.",
                        evidence=raw,
                    )
                )

            if observed_ips:
                public_ips = [ip.ip for ip in observed_ips if ip.classification == "public"]
                private_ips = [ip.ip for ip in observed_ips if ip.classification == "private"]
                reserved_ips = [
                    ip.ip for ip in observed_ips if ip.classification == "reserved"
                ]
                other_internal = [
                    f"{ip.ip} ({ip.classification})"
                    for ip in observed_ips
                    if ip.classification in {"loopback", "link_local", "multicast"}
                ]
                if public_ips:
                    notes.append(
                        f"Observed public IP(s): {', '.join(public_ips)}. These are network observations, not proof of attacker identity or physical location."
                    )
                if private_ips:
                    notes.append(
                        f"Observed private/internal IP(s): {', '.join(private_ips)}."
                    )
                if reserved_ips:
                    notes.append(
                        f"Observed reserved/documentation IP(s): {', '.join(reserved_ips)}. These are not real public source addresses."
                    )
                if other_internal:
                    notes.append(
                        f"Observed non-public special-use IP(s): {', '.join(other_internal)}."
                    )
            else:
                notes.append("No IP addresses were extracted from this hop.")

            hops.append(
                ReceivedHop(
                    hop_index=index + 1,
                    raw=raw,
                    observed_ips=observed_ips,
                    position=position,
                    notes=notes,
                )
            )
            observed_evidence.append(f"Received hop {index + 1}: {raw}")
        except Exception:
            hops.append(
                ReceivedHop(
                    hop_index=index + 1,
                    raw=raw,
                    observed_ips=[],
                    position=None,
                    notes=["This Received header could not be fully analyzed and was skipped safely."],
                )
            )
            indicators.append(
                ForensicIndicator(
                    type="malformed_received_header",
                    severity="low",
                    description="A Received header triggered a parsing error and was isolated.",
                    evidence=raw,
                )
            )

    public_count = sum(
        1
        for hop in hops
        for ip in hop.observed_ips
        if ip.classification == "public"
    )
    if public_count:
        findings.append(
            f"{public_count} public observed IP(s) were extracted from Received headers. "
            "They describe probable source infrastructure along the mail path, not a confirmed attacker."
        )
    findings.append(
        "Received-header hop order is preserved as provided by Module 2 (typically newest hop first)."
    )
    return hops


def _extract_observed_ips(text: str) -> list[ObservedIP]:
    found: list[ObservedIP] = []
    seen: set[str] = set()

    def add(raw_ip: str) -> None:
        try:
            addr = ipaddress.ip_address(raw_ip.strip())
        except ValueError:
            return
        key = str(addr)
        if key in seen:
            return
        seen.add(key)
        found.append(
            ObservedIP(
                ip=key,
                version=addr.version,
                classification=_classify_ip(addr),
                confidence="observed",
            )
        )

    for match in _IPV4.finditer(text or ""):
        add(match.group(0))
    for match in _IPV6_BRACKET.finditer(text or ""):
        add(match.group(1))
    return found


# RFC 1918 site-local IPv4 and IPv6 unique-local addresses.
_PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)

# Documentation / TEST-NET ranges that must never be treated as public sources.
_DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3
    ipaddress.ip_network("2001:db8::/32"),      # IPv6 documentation
    ipaddress.ip_network("3fff::/20"),          # additional IPv6 documentation
)


def _addr_in_networks(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...],
) -> bool:
    return any(addr in network for network in networks if addr.version == network.version)


def _classify_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Classify an observed IP for forensics.

    Values: public, private, reserved, loopback, link_local, multicast.
    Documentation/TEST-NET addresses are reserved, never public.
    """
    if addr.is_unspecified:
        return "reserved"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link_local"
    if addr.is_multicast:
        return "multicast"
    if _addr_in_networks(addr, _DOCUMENTATION_NETWORKS):
        return "reserved"
    if _addr_in_networks(addr, _PRIVATE_NETWORKS):
        return "private"
    if addr.is_reserved or addr.is_private or not addr.is_global:
        return "reserved"
    return "public"


def _apply_auth_scores(
    authentication: AuthenticationAnalysis,
    score_breakdown: list[str],
    findings: list[str],
) -> int:
    added = 0
    if authentication.spf == "fail":
        added += _SCORE_SPF_FAIL
        score_breakdown.append(f"SPF fail: +{_SCORE_SPF_FAIL}")
    elif authentication.spf == "softfail":
        added += _SCORE_SPF_SOFTFAIL
        score_breakdown.append(f"SPF softfail: +{_SCORE_SPF_SOFTFAIL}")
    elif authentication.spf == "permerror":
        added += _SCORE_SPF_PERMERROR
        score_breakdown.append(f"SPF permerror: +{_SCORE_SPF_PERMERROR}")

    if authentication.dkim == "fail":
        added += _SCORE_DKIM_FAIL
        score_breakdown.append(f"DKIM fail: +{_SCORE_DKIM_FAIL}")
    if authentication.dmarc == "fail":
        added += _SCORE_DMARC_FAIL
        score_breakdown.append(f"DMARC fail: +{_SCORE_DMARC_FAIL}")
    if added == 0:
        findings.append("Authentication results did not add forensic risk points.")
    return added


def _apply_sender_scores(
    sender: SenderAnalysis,
    headers: EmailHeaders,
    score_breakdown: list[str],
    findings: list[str],
) -> int:
    added = 0
    if sender.from_domain and sender.reply_to_domain and not _domains_consistent(
        sender.from_domain, sender.reply_to_domain
    ):
        added += _SCORE_FROM_REPLY_TO_MISMATCH
        score_breakdown.append(
            f"From/Reply-To domain mismatch: +{_SCORE_FROM_REPLY_TO_MISMATCH}"
        )
    if sender.from_domain and sender.return_path_domain and not _domains_consistent(
        sender.from_domain, sender.return_path_domain
    ):
        added += _SCORE_FROM_RETURN_PATH_MISMATCH
        score_breakdown.append(
            f"From/Return-Path domain mismatch: +{_SCORE_FROM_RETURN_PATH_MISMATCH}"
        )
    if sender.from_domain and sender.message_id_domain and not _domains_consistent(
        sender.from_domain, sender.message_id_domain
    ):
        added += _SCORE_FROM_MESSAGE_ID_MISMATCH
        score_breakdown.append(
            f"From/Message-ID domain mismatch: +{_SCORE_FROM_MESSAGE_ID_MISMATCH}"
        )

    _, _, from_malformed = _parse_mailbox(headers.from_address)
    _, _, reply_malformed = _parse_mailbox(headers.reply_to)
    _, _, return_malformed = _parse_mailbox(headers.return_path)
    malformed_count = sum(1 for flag in (from_malformed, reply_malformed, return_malformed) if flag)
    if malformed_count:
        points = _SCORE_MALFORMED_ADDRESS * malformed_count
        added += points
        score_breakdown.append(f"Malformed mailbox header(s): +{points}")
    return added


def _apply_header_quality_scores(
    headers: EmailHeaders,
    received_chain: list[ReceivedHop],
    score_breakdown: list[str],
    findings: list[str],
    indicators: list[ForensicIndicator],
) -> int:
    added = 0
    if not headers.from_address:
        added += _SCORE_MISSING_FROM
        score_breakdown.append(f"Missing From header: +{_SCORE_MISSING_FROM}")
        indicators.append(
            ForensicIndicator(
                type="missing_from",
                severity="medium",
                description="The From header is missing.",
                evidence="",
            )
        )
    if not headers.message_id:
        added += _SCORE_MISSING_MESSAGE_ID
        score_breakdown.append(f"Missing Message-ID: +{_SCORE_MISSING_MESSAGE_ID}")
        indicators.append(
            ForensicIndicator(
                type="missing_message_id",
                severity="low",
                description="The Message-ID header is missing.",
                evidence="",
            )
        )

    malformed_hops = sum(
        1
        for hop in received_chain
        if any("typical from/by" in note.lower() or "could not be fully analyzed" in note.lower() for note in hop.notes)
    )
    if malformed_hops:
        points = min(_SCORE_MALFORMED_RECEIVED * malformed_hops, 18)
        added += points
        score_breakdown.append(f"Suspicious or malformed Received header(s): +{points}")
    return added


def _risk_level(score: int) -> str:
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def _confidence(
    headers: EmailHeaders,
    authentication: AuthenticationAnalysis,
    received_chain: list[ReceivedHop],
) -> float:
    value = 0.35
    if headers.from_address:
        value += 0.1
    if headers.message_id:
        value += 0.05
    if received_chain:
        value += 0.15
    auth_known = any(
        result not in {"unknown", "none"}
        for result in (authentication.spf, authentication.dkim, authentication.dmarc)
    )
    if auth_known:
        value += 0.25
    elif headers.authentication_results or headers.received_spf:
        value += 0.1
    return round(min(value, 0.95), 2)


def _parse_mailbox(value: str | None) -> tuple[str | None, str | None, bool]:
    if value is None:
        return None, None, False
    text = value.strip()
    if not text:
        return None, None, False

    try:
        cleaned = text.strip("<>").strip()
        _name, addr = parseaddr(text if "<" in text else f"<{cleaned}>")
        candidate = (addr or "").strip().strip("<>")
        if not candidate:
            match = _EMAIL_IN_TEXT.search(text)
            candidate = match.group(0) if match else ""
        if not candidate or "@" not in candidate:
            return text, None, True
        local, _, domain = candidate.rpartition("@")
        domain = _normalize_domain(domain)
        if not local or not domain or "." not in domain:
            return candidate, domain or None, True
        return candidate.lower(), domain, False
    except Exception:
        return text, None, True


def _message_id_domain(value: str | None) -> str | None:
    if not value or not value.strip():
        return None
    try:
        match = _MESSAGE_ID_DOMAIN.search(value)
        if not match:
            return None
        return _normalize_domain(match.group(1))
    except Exception:
        return None


def _normalize_domain(domain: str | None) -> str | None:
    if not domain:
        return None
    cleaned = domain.strip().strip(".").strip("[]").lower()
    if cleaned.startswith("ipv6:"):
        return None
    return cleaned or None


def _registrable_domain(domain: str) -> str:
    parts = [part for part in domain.lower().split(".") if part]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain.lower()


def _domains_consistent(left: str, right: str) -> bool:
    if left.lower() == right.lower():
        return True
    return _registrable_domain(left) == _registrable_domain(right)


def _tokens(pattern: re.Pattern[str], text: str, allowed: set[str]) -> list[str]:
    found: list[str] = []
    try:
        for match in pattern.finditer(text or ""):
            value = match.group(1).lower()
            if value in allowed:
                found.append(value)
    except Exception:
        return found
    return found


def _worst(values: list[str], rank: dict[str, int], default: str) -> str:
    if not values:
        return default
    return min(values, key=lambda item: rank.get(item, 99))


def _auth_evidence(headers: EmailHeaders, mechanism: str) -> str:
    parts: list[str] = []
    parts.extend(headers.authentication_results)
    if mechanism == "spf":
        parts.extend(headers.received_spf)
    return "; ".join(parts)[:500]
