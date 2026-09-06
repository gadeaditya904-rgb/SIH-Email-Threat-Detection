"""Parse .eml bytes into structured header, body, and URL data.

Later modules can consume this output for header forensics, authentication
analysis, IP extraction, domain intelligence, and threat scoring without
changing the upload contract.
"""

from __future__ import annotations

import html as html_lib
import re
from email import policy
from email.message import EmailMessage, Message
from email.parser import BytesParser

from models.email import EmailBody, EmailHeaders, EmailParseResponse

MAX_EML_SIZE_BYTES = 10 * 1024 * 1024

_HEADER_LINE = re.compile(rb"(?m)^[A-Za-z][A-Za-z0-9-]*:\s*\S")
_HTTP_URL = re.compile(r"https?://[^\s<>\"'\\)\]\}]+", re.IGNORECASE)
_HREF_OR_SRC = re.compile(
    r"""(?:href|src)\s*=\s*(?:["']([^"']+)["']|([^\s>]+))""",
    re.IGNORECASE,
)


class EmailParseError(Exception):
    """Raised when an uploaded file cannot be treated as a valid email."""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


def parse_eml_bytes(raw: bytes, filename: str) -> EmailParseResponse:
    if not raw or not raw.strip():
        raise EmailParseError("The uploaded file is empty.")

    if not _HEADER_LINE.search(raw):
        raise EmailParseError(
            "The file does not look like a valid .eml message (no RFC 5322 headers found)."
        )

    message = _parse_message(raw)
    headers = _extract_headers(message)
    plain_text, html_body = _extract_bodies(message)
    urls = _extract_urls(plain_text, html_body)

    return EmailParseResponse(
        filename=filename,
        headers=headers,
        body=EmailBody(
            plain_text=_empty_to_none(plain_text),
            html=_empty_to_none(html_body),
        ),
        urls=urls,
    )


def _parse_message(raw: bytes) -> Message:
    try:
        return BytesParser(policy=policy.default).parsebytes(raw)
    except Exception:
        try:
            return BytesParser(policy=policy.compat32).parsebytes(raw)
        except Exception as exc:
            raise EmailParseError(
                f"Unable to parse the .eml file: {exc}"
            ) from exc


def _header_value(message: Message, name: str) -> str | None:
    value = message.get(name)
    if value is None:
        return None
    text = _normalize_header_text(str(value))
    return text or None


def _header_values(message: Message, name: str) -> list[str]:
    values = message.get_all(name) or []
    cleaned: list[str] = []
    for value in values:
        text = _normalize_header_text(str(value))
        if text:
            cleaned.append(text)
    return cleaned


def _normalize_header_text(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _extract_headers(message: Message) -> EmailHeaders:
    return EmailHeaders.model_validate(
        {
            "from": _header_value(message, "From"),
            "to": _header_value(message, "To"),
            "cc": _header_value(message, "Cc"),
            "subject": _header_value(message, "Subject"),
            "date": _header_value(message, "Date"),
            "reply-to": _header_value(message, "Reply-To"),
            "message-id": _header_value(message, "Message-ID"),
            "return-path": _header_value(message, "Return-Path"),
            "received": _header_values(message, "Received"),
            "authentication-results": _header_values(message, "Authentication-Results"),
            "received-spf": _header_values(message, "Received-SPF"),
            "dkim-signature": _header_values(message, "DKIM-Signature"),
        }
    )


def _extract_bodies(message: Message) -> tuple[str, str]:
    plain_parts: list[str] = []
    html_parts: list[str] = []

    if isinstance(message, EmailMessage):
        try:
            plain_body = message.get_body(preferencelist=("plain",))
            html_body = message.get_body(preferencelist=("html",))
            if plain_body is not None:
                text = _part_as_text(plain_body)
                if text:
                    plain_parts.append(text)
            if html_body is not None:
                text = _part_as_text(html_body)
                if text:
                    html_parts.append(text)
        except Exception:
            plain_parts = []
            html_parts = []

    if not plain_parts and not html_parts:
        _walk_text_parts(message, plain_parts, html_parts)

    return "\n\n".join(plain_parts).strip(), "\n\n".join(html_parts).strip()


def _walk_text_parts(
    message: Message, plain_parts: list[str], html_parts: list[str]
) -> None:
    if message.is_multipart():
        for part in message.walk():
            if part.is_multipart():
                continue
            _collect_text_part(part, plain_parts, html_parts)
        return
    _collect_text_part(message, plain_parts, html_parts)


def _collect_text_part(
    part: Message, plain_parts: list[str], html_parts: list[str]
) -> None:
    disposition = str(part.get("Content-Disposition") or "").lower()
    if "attachment" in disposition:
        return

    content_type = part.get_content_type()
    text = _part_as_text(part)
    if not text:
        return
    if content_type == "text/plain":
        plain_parts.append(text)
    elif content_type == "text/html":
        html_parts.append(text)


def _part_as_text(part: Message) -> str:
    try:
        if isinstance(part, EmailMessage):
            content = part.get_content()
            if isinstance(content, str):
                return content.strip()
            if isinstance(content, bytes):
                return content.decode("utf-8", errors="replace").strip()
    except Exception:
        pass

    payload = part.get_payload(decode=True)
    if payload is None:
        raw_payload = part.get_payload()
        return raw_payload.strip() if isinstance(raw_payload, str) else ""

    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace").strip()
    except LookupError:
        return payload.decode("utf-8", errors="replace").strip()


def _extract_urls(plain_text: str, html_body: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()

    def add(url: str) -> None:
        cleaned = _normalize_url(url)
        if not cleaned or cleaned in seen:
            return
        seen.add(cleaned)
        found.append(cleaned)

    for match in _HTTP_URL.finditer(plain_text or ""):
        add(match.group(0))

    html_unescaped = html_lib.unescape(html_body or "")
    for match in _HTTP_URL.finditer(html_unescaped):
        add(match.group(0))
    for match in _HREF_OR_SRC.finditer(html_unescaped):
        candidate = match.group(1) or match.group(2) or ""
        if candidate.lower().startswith(("http://", "https://")):
            add(candidate)

    return found


def _normalize_url(url: str) -> str:
    return html_lib.unescape(url).rstrip(".,;:)>]}\\'\"")


def _empty_to_none(value: str) -> str | None:
    return value if value else None
