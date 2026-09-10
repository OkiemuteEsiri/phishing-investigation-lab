# Phishing Investigation Lab

A recruiter-facing defensive security engineering project for **phishing triage, detection engineering, incident response, evidence preservation, and risk-based remediation**.

This repository demonstrates how a security analyst can turn message metadata and user-interaction evidence into a repeatable investigation workflow without relying on unsafe offensive tooling. All included data is synthetic. The project performs no phishing, credential collection, mailbox modification, payload execution, live reputation lookup, or production targeting.

## Problem statement

Phishing investigations often fail when teams treat individual signals—such as a DMARC failure, unusual URL, attachment extension, or user click—as a definitive verdict. Effective incident response instead requires normalization, evidence preservation, corroboration, risk prioritization, containment proportional to impact, and validation before closure.

This lab implements that workflow as code.

## Capabilities

- Validated immutable message-evidence models.
- UTC timestamp normalization and IP/URL validation.
- Fail-closed JSON ingestion and duplicate message-ID detection.
- Deterministic phishing-investigation scoring from 0–100.
- Explainable evidence for every risk decision.
- Separate **severity**, **disposition**, and **evidence** rather than collapsing them into one label.
- Synthetic SPF, DKIM, DMARC, Reply-To, URL, attachment and user-interaction evidence.
- Evidence-preserving deterministic finding IDs.
- Portfolio-level severity/disposition metrics.
- Markdown executive and technical reporting.
- Offline CLI execution.
- Ten unit tests covering normal, suspicious, critical and malformed-input cases.
- Architecture, methodology, containment, remediation and validation documentation.
- Least-privilege GitHub Actions workflow.

## Architecture

```text
Synthetic JSON evidence
        |
        v
  src/io.py
  validation + deduplication
        |
        v
  src/models.py
  canonical evidence objects
        |
        v
  src/analyzer.py
  deterministic triage + ATT&CK context
        |
        +--------------------+
        |                    |
        v                    v
portfolio metrics      investigation findings
        |                    |
        +----------+---------+
                   v
            src/reporting.py
                   |
                   v
          Markdown assessment
```

## Repository structure

```text
.
├── .github/workflows/ci.yml
├── data/
│   └── synthetic_messages.json
├── docs/
│   └── architecture-methodology.md
├── reports/
│   └── example-assessment.md
├── src/
│   ├── analyzer.py
│   ├── cli.py
│   ├── io.py
│   ├── models.py
│   └── reporting.py
└── tests/
    └── test_analyzer.py
```

## Risk model

The engine uses deterministic weights to prioritize investigation. Signals include:

| Signal | Security meaning |
|---|---|
| DMARC failure | Possible sender-authentication concern |
| SPF failure/softfail | Sending-path anomaly requiring context |
| DKIM failure | Message-integrity/authentication concern |
| Sender/Reply-To mismatch | Potential impersonation or response redirection |
| Elevated-risk synthetic URL metadata | Link-based investigation signal |
| Script/executable-like attachment name | Attachment-based investigation signal |
| Recorded user click | Raises urgency for downstream telemetry review |
| Reported credential submission | Material identity-risk escalation |

Scores are bounded at 100 and are used for **triage priority**, not as a probability that compromise occurred.

## MITRE ATT&CK context

The lab maps relevant findings to:

- **T1566.001 — Spearphishing Attachment**
- **T1566.002 — Spearphishing Link**
- **T1204.001 — Malicious Link / User Execution context**
- **T1056.003 — Web Portal Capture context**
- **T1078 — Valid Accounts** as potential downstream identity risk

ATT&CK mappings provide threat context only. They do not claim that a technique occurred in a real environment.

## Usage

Run the included synthetic assessment:

```bash
python -m src.cli data/synthetic_messages.json --output reports/generated-report.md
```

Run the unit tests:

```bash
python -m unittest discover -s tests -v
```

The CLI reads only local JSON and writes a Markdown report. It performs no network activity.

## Investigation methodology

1. **Preserve evidence** — retain original message metadata, stable identifiers, authentication results, URLs, attachment names, timestamps and reported user actions.
2. **Validate authenticity signals** — review SPF/DKIM/DMARC and sender/reply relationships while allowing for legitimate forwarding and mailing-list behavior.
3. **Assess delivery content safely** — classify metadata without fetching, opening, detonating or weaponizing content.
4. **Correlate user interaction** — use click, proxy, browser, endpoint and identity evidence to understand actual exposure.
5. **Contain proportionately** — block confirmed malicious indicators and perform credential/session containment only when evidence or policy supports it.
6. **Validate recovery** — confirm related messages, identities, endpoints and sessions are reviewed before closure.

Detailed methodology is documented in `docs/architecture-methodology.md`.

## Example outcome

The synthetic dataset contains both routine and elevated-risk messages. The included example report demonstrates how a high-priority case can combine mail-authentication failures, sender/Reply-To mismatch, suspicious link metadata and a recorded click, while a critical identity-focused case includes reported credential submission.

The report deliberately distinguishes **investigation evidence** from **proof of compromise**.

## Remediation and validation workflow

For a confirmed phishing incident, an appropriate response can include:

- preserve message and related telemetry;
- identify related recipients/messages;
- block confirmed malicious senders, domains, URLs or attachment indicators through authorized controls;
- review endpoint/browser/proxy activity after a click;
- review identity-provider sign-ins and session activity;
- reset credentials and revoke active sessions when credential exposure is supported by evidence or policy;
- document false positives and tuning opportunities;
- confirm no unexplained follow-on activity remains before closure.

## Security engineering design choices

### Evidence preservation
Findings retain explicit evidence strings and stable source message IDs so an analyst can trace a risk decision back to the record that generated it.

### Fail-closed validation
Malformed timestamps, IP addresses, URLs, authentication states, duplicate message IDs and invalid record structures raise errors rather than silently entering the investigation pipeline.

### Deterministic IDs
Finding identifiers are derived from stable message/title inputs. Reprocessing the same synthetic case produces the same finding ID, supporting reconciliation and repeatable reporting.

### No automatic containment
The engine never resets credentials, revokes sessions, blocks indicators or deletes mail. Those actions require evidence, authorization and environment-specific controls.

## Tests

The unit-test suite covers:

- benign baseline handling;
- DMARC-driven risk elevation;
- Reply-To mismatch detection;
- attachment-based ATT&CK mapping;
- click-based ATT&CK mapping;
- credential-submission escalation;
- bounded risk scoring;
- deterministic finding IDs;
- portfolio metric aggregation;
- fail-closed timestamp validation.

## CI/CD security checks

The GitHub Actions workflow uses read-only repository permissions and executes:

1. Python compilation checks.
2. Unit-test discovery.
3. An offline CLI smoke test against the synthetic dataset.

Workflow presence does not imply a successful run; commit status should be checked independently.

## Skills demonstrated

- Phishing investigation and SOC triage
- Incident response workflow design
- Email-security control interpretation
- Detection engineering
- Evidence normalization and validation
- Risk scoring and prioritization
- MITRE ATT&CK mapping
- Python security automation
- Unit testing
- Security reporting
- CI/CD security hygiene
- Remediation and revalidation design

## Limitations

This is a portable defensive lab, not a production mail-security platform. It intentionally excludes live DNS/reputation APIs, sandbox detonation, SIEM/EDR integrations, mailbox remediation, credential/session actions, message delivery, payload execution and real-user data. Heuristic scores should never replace analyst judgment or corroborating telemetry.

## Roadmap

Future safe extensions could include:

- provider-neutral adapters for exported email-gateway telemetry;
- offline IOC enrichment from curated local intelligence snapshots;
- message-cluster and campaign correlation using synthetic data;
- analyst disposition tracking and false-positive metrics;
- detection coverage matrices across email, endpoint, proxy and identity sources;
- JSON/SARIF report export for downstream defensive workflows.

## Safety statement

All examples are synthetic and intended for defensive security education, engineering and incident-response portfolio demonstration. No employer/client data, real credentials, live phishing infrastructure, exploit payloads or production targeting are included.
