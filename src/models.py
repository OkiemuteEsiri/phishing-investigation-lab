from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from ipaddress import ip_address
from urllib.parse import urlparse

ALLOWED_DISPOSITIONS = {"malicious", "suspicious", "benign", "unknown"}
ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def parse_utc(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return dt.astimezone(timezone.utc)


def validate_ip(value: str) -> str:
    return str(ip_address(value))


def validate_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("URL must be absolute http/https")
    return value


@dataclass(frozen=True)
class MessageEvidence:
    message_id: str
    sender: str
    recipient: str
    subject: str
    received_at: str
    source_ip: str
    spf: str
    dkim: str
    dmarc: str
    reply_to: str | None = None
    urls: tuple[str, ...] = field(default_factory=tuple)
    attachment_names: tuple[str, ...] = field(default_factory=tuple)
    user_clicked: bool = False
    user_submitted_credentials: bool = False

    def __post_init__(self) -> None:
        if not self.message_id.strip() or "@" not in self.sender or "@" not in self.recipient:
            raise ValueError("message_id, sender and recipient are required")
        parse_utc(self.received_at)
        validate_ip(self.source_ip)
        for status in (self.spf, self.dkim, self.dmarc):
            if status.lower() not in {"pass", "fail", "softfail", "neutral", "none"}:
                raise ValueError("invalid authentication status")
        for url in self.urls:
            validate_url(url)


@dataclass(frozen=True)
class Finding:
    finding_id: str
    message_id: str
    severity: str
    title: str
    disposition: str
    score: int
    evidence: tuple[str, ...]
    attack_techniques: tuple[str, ...]
    remediation: str
    validation: str

    @staticmethod
    def deterministic_id(message_id: str, title: str) -> str:
        return sha256(f"{message_id}|{title}".encode()).hexdigest()[:16]
