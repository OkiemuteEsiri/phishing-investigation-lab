from __future__ import annotations

from .analyzer import portfolio_metrics
from .models import Finding


def render_markdown(findings: list[Finding]) -> str:
    metrics = portfolio_metrics(findings)
    lines = [
        "# Phishing Investigation Report",
        "",
        "## Executive summary",
        f"- Messages assessed: {metrics['total_messages']}",
        f"- Critical/High findings: {metrics['critical_high']}",
        f"- Highest risk score: {metrics['highest_score']}/100",
        "",
        "## Findings",
    ]
    for finding in sorted(findings, key=lambda f: f.score, reverse=True):
        lines.extend([
            "",
            f"### {finding.message_id} — {finding.severity.upper()} ({finding.score}/100)",
            f"Disposition: **{finding.disposition}**",
            f"MITRE ATT&CK context: {', '.join(finding.attack_techniques) if finding.attack_techniques else 'None assigned'}",
            "",
            "Evidence:",
        ])
        lines.extend(f"- {item}" for item in (finding.evidence or ("No elevated-risk signals identified",)))
        lines.extend([
            "",
            f"Remediation: {finding.remediation}",
            f"Validation: {finding.validation}",
        ])
    lines.extend([
        "",
        "## Limitations",
        "This lab uses synthetic evidence and deterministic heuristics. Findings are investigation signals, not proof of compromise. Production decisions require corroborating mail, endpoint, identity, proxy and user-context telemetry.",
    ])
    return "\n".join(lines) + "\n"
