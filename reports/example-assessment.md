# Example Phishing Investigation Assessment

> Synthetic example only. No production email, identities, infrastructure, credentials, or client data are represented.

## Executive summary

Four synthetic messages were reviewed using deterministic, evidence-preserving triage logic. Two messages require elevated investigation priority because they combine authentication failures, anomalous sender/reply behavior, suspicious link metadata, and recorded user interaction. One synthetic message includes reported credential submission and therefore requires immediate identity-focused containment and validation in a real incident process.

## Priority observations

### SYN-003 — Critical
- DMARC failed and SPF soft-failed.
- URL metadata matched the lab's elevated-risk synthetic TLD set.
- A user click and reported credential submission were recorded.
- ATT&CK context: T1566.002, T1204.001, T1056.003, T1078.

Recommended response: preserve email and identity evidence, investigate related sign-ins and browser/proxy telemetry, revoke sessions/reset credentials where exposure is corroborated, search for related messages, and monitor for follow-on activity.

Validation standard: containment is not complete until related identity sessions are reviewed, post-event activity is explained, malicious indicators are blocked or otherwise controlled, and no unexplained persistence or lateral activity remains.

### SYN-001 — High
- SPF, DKIM, and DMARC failed.
- Reply-To domain differs from sender domain.
- URL metadata matched the synthetic elevated-risk set.
- User click recorded.
- ATT&CK context: T1566.002 and T1204.001.

Recommended response: preserve message evidence, validate user interaction, correlate proxy/browser/endpoint telemetry, and block confirmed malicious indicators through approved controls.

## Benign baseline examples

SYN-002 and SYN-004 model routine mail with passing authentication and no elevated-risk user-interaction signals. They exist to show that the engine can retain low-risk/benign observations rather than force every message into an incident classification.

## Analyst note

The score prioritizes investigation; it is not a compromise probability. Mail-authentication failures can have legitimate explanations, and a click does not prove execution or credential loss. Escalation should remain evidence-driven.
