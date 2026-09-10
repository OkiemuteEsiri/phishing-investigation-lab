# Architecture and Investigation Methodology

## Purpose

This repository demonstrates a defensive, evidence-driven phishing investigation workflow using synthetic data. It is designed for detection engineering, SOC triage, incident response, and security engineering portfolios. It does not perform phishing, credential capture, message delivery, mailbox modification, or live infrastructure interaction.

## Architecture

1. `src/models.py` validates message evidence, timestamps, IP addresses, URLs, and mail-authentication states.
2. `src/io.py` ingests synthetic JSON evidence and rejects duplicate message identifiers or malformed records.
3. `src/analyzer.py` applies deterministic investigation signals and produces explainable findings.
4. `src/reporting.py` converts findings into an executive and technical Markdown report.
5. `tests/` validates core controls and fail-closed behavior.
6. `data/` contains non-functional synthetic evidence using reserved/example address space and domains.

## Investigation workflow

The assessment intentionally separates **signals** from **conclusions**. A failed DMARC result, unusual Reply-To domain, suspicious URL, or user click can raise priority, but none is independently treated as proof of malicious activity. Analysts should correlate email-gateway evidence with endpoint, proxy, DNS, identity-provider, browser, and user-context telemetry.

### Phase 1 — Preserve evidence

Preserve the original message, headers, gateway trace, attachment metadata, URLs, sender/recipient context, timestamps, and user-reported actions. Evidence should retain stable identifiers so later containment and recovery decisions can be traced back to source telemetry.

### Phase 2 — Validate sender and message authenticity

Review SPF, DKIM and DMARC results, but account for legitimate forwarding and mailing-list behavior. Compare sender, Return-Path and Reply-To domains, and validate whether the sending infrastructure is expected for the organization or service being represented.

### Phase 3 — Evaluate delivery content

Review link destinations and attachment types using safe analysis methods. The lab only classifies metadata and does not fetch, execute, detonate, or weaponize content. Suspicious attachment extensions are treated as triage signals rather than executed artifacts.

### Phase 4 — Determine user interaction

Correlate click telemetry, browser/proxy events, endpoint process evidence, and identity sign-ins. A click increases urgency; reported credential submission materially raises incident severity and should trigger evidence-based identity containment.

### Phase 5 — Contain proportionately

For confirmed malicious indicators, remove or block messages and indicators through authorized controls. Credential resets, token/session revocation, endpoint isolation, or broad blocking should be driven by corroborating evidence and organizational playbooks rather than heuristic score alone.

### Phase 6 — Validate recovery

Closure requires evidence that malicious messages/indicators are contained, exposed credentials or sessions were addressed where applicable, affected endpoints and identities were reviewed, and monitoring found no unexplained follow-on activity.

## Risk model

The deterministic score ranges from 0–100. It weights authentication failures, Reply-To mismatch, elevated-risk synthetic URL metadata, executable/script-like attachment names, recorded clicks, and reported credential submission. The score is an investigation-priority mechanism; it is not a probability of compromise.

## MITRE ATT&CK context

- T1566.001 — Spearphishing Attachment
- T1566.002 — Spearphishing Link
- T1204.001 — Malicious Link / User Execution context
- T1056.003 — Web Portal Capture context when credential submission is reported
- T1078 — Valid Accounts as potential downstream identity risk

Mappings describe relevant adversary behavior and investigation context. They do not assert that an ATT&CK technique occurred in any real environment.

## Remediation and validation principles

- Preserve evidence before destructive containment where practical.
- Block confirmed malicious indicators through approved controls.
- Search for related messages and impacted recipients.
- Reset credentials and revoke active sessions only when exposure is supported by evidence or policy.
- Investigate post-click endpoint and identity telemetry.
- Revalidate mail controls and user protection after corrective actions.
- Record false positives and tuning decisions to improve detection quality.

## Limitations

This lab uses synthetic evidence and deterministic heuristics. It does not include live reputation feeds, sandbox detonation, message trace APIs, SIEM connectors, mailbox remediation, EDR actions, or production identity integrations. These are deliberate safety and portability constraints.
