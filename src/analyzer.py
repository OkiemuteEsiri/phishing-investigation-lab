from __future__ import annotations

from collections import Counter
from urllib.parse import urlparse

from .models import Finding, MessageEvidence

HIGH_RISK_TLDS = {"zip", "mov", "top", "click"}
EXECUTABLE_EXTENSIONS = {".exe", ".js", ".vbs", ".scr", ".iso", ".lnk"}


def _domain(address: str) -> str:
    return address.rsplit("@", 1)[-1].lower()


def _score_message(message: MessageEvidence) -> tuple[int, list[str], list[str]]:
    score = 0
    evidence: list[str] = []
    techniques: list[str] = []

    if message.dmarc.lower() == "fail":
        score += 25
        evidence.append("DMARC failed")
    if message.spf.lower() in {"fail", "softfail"}:
        score += 15
        evidence.append(f"SPF {message.spf.lower()}")
    if message.dkim.lower() == "fail":
        score += 10
        evidence.append("DKIM failed")

    if message.reply_to and _domain(message.reply_to) != _domain(message.sender):
        score += 15
        evidence.append("Reply-To domain differs from sender domain")
        techniques.append("T1566.002")

    suspicious_urls = []
    for url in message.urls:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        tld = host.rsplit(".", 1)[-1] if "." in host else ""
        if tld in HIGH_RISK_TLDS:
            suspicious_urls.append(host)
    if suspicious_urls:
        score += 20
        evidence.append("Message contains URL on elevated-risk synthetic TLD set")
        techniques.append("T1566.002")

    risky_attachments = [name for name in message.attachment_names if any(name.lower().endswith(ext) for ext in EXECUTABLE_EXTENSIONS)]
    if risky_attachments:
        score += 25
        evidence.append("Message contains executable or script-like attachment")
        techniques.append("T1566.001")

    if message.user_clicked:
        score += 15
        evidence.append("User click recorded")
        techniques.append("T1204.001")
    if message.user_submitted_credentials:
        score += 30
        evidence.append("Credential submission reported")
        techniques.extend(["T1056.003", "T1078"])

    return min(score, 100), evidence, sorted(set(techniques))


def analyze(message: MessageEvidence) -> Finding:
    score, evidence, techniques = _score_message(message)
    if message.user_submitted_credentials or score >= 80:
        severity, disposition = "critical", "malicious"
    elif score >= 60:
        severity, disposition = "high", "suspicious"
    elif score >= 35:
        severity, disposition = "medium", "suspicious"
    elif score > 0:
        severity, disposition = "low", "unknown"
    else:
        severity, disposition = "info", "benign"

    title = "Phishing investigation assessment"
    remediation = (
        "Preserve the message and related telemetry; block confirmed malicious indicators; reset credentials and revoke sessions only when evidence supports account exposure."
    )
    validation = (
        "Confirm mail-authentication results, review click/sign-in telemetry, verify indicator disposition, and document containment/recovery evidence before closure."
    )
    return Finding(
        finding_id=Finding.deterministic_id(message.message_id, title),
        message_id=message.message_id,
        severity=severity,
        title=title,
        disposition=disposition,
        score=score,
        evidence=tuple(evidence),
        attack_techniques=tuple(techniques),
        remediation=remediation,
        validation=validation,
    )


def portfolio_metrics(findings: list[Finding]) -> dict:
    severities = Counter(f.severity for f in findings)
    dispositions = Counter(f.disposition for f in findings)
    return {
        "total_messages": len(findings),
        "critical_high": severities["critical"] + severities["high"],
        "by_severity": dict(severities),
        "by_disposition": dict(dispositions),
        "highest_score": max((f.score for f in findings), default=0),
    }
