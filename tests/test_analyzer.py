import unittest

from src.analyzer import analyze, portfolio_metrics
from src.models import MessageEvidence


def msg(**overrides):
    base = dict(
        message_id="T-1",
        sender="user@example.test",
        recipient="analyst@example.test",
        subject="Test",
        received_at="2026-09-01T10:00:00Z",
        source_ip="203.0.113.5",
        spf="pass",
        dkim="pass",
        dmarc="pass",
        reply_to="user@example.test",
        urls=(),
        attachment_names=(),
        user_clicked=False,
        user_submitted_credentials=False,
    )
    base.update(overrides)
    return MessageEvidence(**base)


class AnalyzerTests(unittest.TestCase):
    def test_clean_message_is_benign(self):
        finding = analyze(msg())
        self.assertEqual(finding.disposition, "benign")
        self.assertEqual(finding.score, 0)

    def test_dmarc_failure_increases_score(self):
        self.assertGreater(analyze(msg(dmarc="fail")).score, 0)

    def test_reply_to_mismatch_maps_link_phishing(self):
        finding = analyze(msg(reply_to="reply@other.test"))
        self.assertIn("T1566.002", finding.attack_techniques)

    def test_risky_attachment_maps_spearphishing_attachment(self):
        finding = analyze(msg(attachment_names=("document.js",)))
        self.assertIn("T1566.001", finding.attack_techniques)

    def test_click_maps_user_execution(self):
        finding = analyze(msg(user_clicked=True))
        self.assertIn("T1204.001", finding.attack_techniques)

    def test_credential_submission_is_critical(self):
        finding = analyze(msg(user_submitted_credentials=True))
        self.assertEqual(finding.severity, "critical")
        self.assertIn("T1056.003", finding.attack_techniques)

    def test_score_is_bounded(self):
        finding = analyze(msg(dmarc="fail", spf="fail", dkim="fail", reply_to="x@other.test", urls=("https://x.click/a",), attachment_names=("x.js",), user_clicked=True, user_submitted_credentials=True))
        self.assertLessEqual(finding.score, 100)

    def test_finding_id_is_deterministic(self):
        self.assertEqual(analyze(msg()).finding_id, analyze(msg()).finding_id)

    def test_metrics_count_high_critical(self):
        findings = [analyze(msg(message_id="1")), analyze(msg(message_id="2", user_submitted_credentials=True))]
        self.assertEqual(portfolio_metrics(findings)["critical_high"], 1)

    def test_invalid_timestamp_fails_closed(self):
        with self.assertRaises(ValueError):
            msg(received_at="2026-09-01T10:00:00")


if __name__ == "__main__":
    unittest.main()
