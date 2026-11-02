"""Narrow public-monitor tests; never execute a package, sign, install, or contact an API."""
import base64
import copy
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import shutil
import unittest
from unittest.mock import patch

import manifest_monitor as m


class MonitorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        folder = Path(os.environ["P1_MONITOR_FIXTURE_DIRECTORY"])
        cls.raw_manifest = (folder / "manifest.json").read_bytes()
        cls.raw_index = (folder / "release-index.json").read_bytes()
        cls.manifest = m.parse_json(cls.raw_manifest, m.MAX_MANIFEST)
        cls.now = m.utc(cls.manifest["publishedUtc"]) + dt.timedelta(hours=1)
        cls.expiry = m.utc(cls.manifest["expiresUtc"])
        cls.openssl = os.environ.get("P1_MONITOR_OPENSSL", "openssl")

    def verify(self, data, signature):
        m.openssl_verify(data, signature, executable=self.openssl)

    def inspect(self, now=None):
        return m.inspect_metadata(self.raw_manifest, self.raw_index, now or self.now, self.verify)

    def reject(self, manifest, code):
        with self.assertRaisesRegex(m.MonitorError, "^" + code + "$"):
            m.validate_manifest(manifest, self.now, self.verify)

    def test_accepted_real_public_metadata(self):
        result = self.inspect()
        self.assertEqual("OK", result["status"])
        self.assertEqual(11, result["childManifestsVerified"])
        self.assertFalse(result["payloadDownloaded"])
        self.assertFalse(result["installedOrSigned"])

    def test_t14(self):
        self.assertEqual("T14", self.inspect(self.expiry - dt.timedelta(days=14))["status"])

    def test_t7(self):
        self.assertEqual("T7", self.inspect(self.expiry - dt.timedelta(days=7))["status"])

    def test_hard_expiry(self):
        self.assertEqual("EXPIRED", self.inspect(self.expiry)["status"])

    def test_expired_after_day(self):
        self.assertEqual("EXPIRED", self.inspect(self.expiry + dt.timedelta(days=1))["status"])

    def test_unknown_publisher(self):
        value = copy.deepcopy(self.manifest); value["publisherKeyId"] = "wrong-key"
        self.reject(value, "PUBLISHER_UNTRUSTED")

    def test_real_signature_tamper(self):
        value = copy.deepcopy(self.manifest)
        signed = bytearray(base64.b64decode(value["manifestSignature"])); signed[0] ^= 1
        value["manifestSignature"] = base64.b64encode(signed).decode()
        self.reject(value, "RSA_SIGNATURE_INVALID")

    def test_real_signed_content_tamper(self):
        value = copy.deepcopy(self.manifest); value["releaseNotes"] += " tampered"
        self.reject(value, "RSA_SIGNATURE_INVALID")

    def test_index_tamper(self):
        tampered = bytearray(self.raw_index); tampered[100] ^= 1
        with self.assertRaisesRegex(m.MonitorError, "^INDEX_HASH_INVALID$"):
            m.inspect_metadata(self.raw_manifest, bytes(tampered), self.now, self.verify)

    def test_duplicate_json(self):
        with self.assertRaisesRegex(m.MonitorError, "^JSON_DUPLICATE_FIELD$"):
            m.parse_json(b'{"sequence":1009,"sequence":1010}', m.MAX_MANIFEST)

    def test_malformed_json(self):
        with self.assertRaisesRegex(m.MonitorError, "^JSON_INVALID$"):
            m.parse_json(b'{bad', m.MAX_MANIFEST)

    def test_json_nan(self):
        with self.assertRaisesRegex(m.MonitorError, "^JSON_NUMBER_INVALID$"):
            m.parse_json(b'{"value":NaN}', m.MAX_MANIFEST)

    def test_size_limit(self):
        with self.assertRaisesRegex(m.MonitorError, "^JSON_SIZE_INVALID$"):
            m.parse_json(b' ' * (m.MAX_MANIFEST + 1), m.MAX_MANIFEST)

    def test_unknown_field(self):
        value = copy.deepcopy(self.manifest); value["unsignedExtra"] = "not accepted"
        self.reject(value, "MANIFEST_FIELDS_INVALID")

    def test_negative_sequence(self):
        value = copy.deepcopy(self.manifest); value["sequence"] = -1
        self.reject(value, "SEQUENCE_ROLLBACK")

    def test_old_sequence(self):
        value = copy.deepcopy(self.manifest); value["sequence"] = m.MINIMUM_SEQUENCE - 1
        self.reject(value, "SEQUENCE_ROLLBACK")

    def test_boolean_sequence(self):
        value = copy.deepcopy(self.manifest); value["sequence"] = True
        self.reject(value, "SEQUENCE_ROLLBACK")

    def test_sequence_overflow(self):
        value = copy.deepcopy(self.manifest); value["sequence"] = 2**63
        self.reject(value, "SEQUENCE_ROLLBACK")

    def test_version_rollback(self):
        value = copy.deepcopy(self.manifest); value["version"] = "1.0.0.8"
        self.reject(value, "VERSION_ROLLBACK")

    def test_version_bad(self):
        value = copy.deepcopy(self.manifest); value["version"] = "1.0.0.9;command"
        self.reject(value, "VERSION_INVALID")

    def test_package_traversal(self):
        value = copy.deepcopy(self.manifest); value["packageName"] = "../manifest.json"
        self.reject(value, "PACKAGE_NAME_INVALID")

    def test_package_size(self):
        value = copy.deepcopy(self.manifest); value["packageLength"] = m.MAX_PART + 1
        self.reject(value, "PACKAGE_SIZE_INVALID")

    def test_future_publication(self):
        value = copy.deepcopy(self.manifest)
        value["publishedUtc"] = (self.now + dt.timedelta(hours=1)).isoformat()
        self.reject(value, "MANIFEST_TIME_INVALID")

    def test_non_utc(self):
        value = copy.deepcopy(self.manifest); value["expiresUtc"] = "2026-12-02T14:31:24+07:00"
        self.reject(value, "UTC_REQUIRED")

    def test_signature_encoding(self):
        value = copy.deepcopy(self.manifest); value["manifestSignature"] = "!" * 512
        self.reject(value, "SIGNATURE_INVALID")

    def test_http_rejected(self):
        with self.assertRaisesRegex(m.MonitorError, "^DOWNLOAD_URL_REJECTED$"):
            m.safe_download_url("http://github.com/" + m.REPOSITORY + "/releases/latest/download/manifest.json")

    def test_lookalike_host_rejected(self):
        with self.assertRaisesRegex(m.MonitorError, "^DOWNLOAD_HOST_REJECTED$"):
            m.safe_download_url("https://github.com.evil.invalid/" + m.REPOSITORY + "/releases/download/manifest.json")

    def test_other_repository_rejected(self):
        with self.assertRaisesRegex(m.MonitorError, "^DOWNLOAD_HOST_REJECTED$"):
            m.safe_download_url("https://github.com/other/repo/releases/latest/download/manifest.json")

    def test_credentials_rejected(self):
        with self.assertRaisesRegex(m.MonitorError, "^DOWNLOAD_URL_REJECTED$"):
            m.safe_download_url("https://user:secret@github.com/" + m.REPOSITORY + "/releases/download/manifest.json")

    def test_cdn_allowed(self):
        m.safe_download_url("https://release-assets.githubusercontent.com/github-production-release-asset/123/abc?sig=public")

    def test_api_no_release_mutation(self):
        with self.assertRaisesRegex(m.MonitorError, "^API_PATH_REJECTED$"):
            m.github_api("PATCH", "/repos/" + m.REPOSITORY + "/releases/123", "not-a-token", {})

    def test_notification_dedup_and_t7_escalation(self):
        calls = []
        issue = {"number": 42, "title": m.ISSUE_TITLE,
                 "body": m.ISSUE_MARKER + "\n<!-- last-level:T14 -->"}
        def api(method, path, token, data=None):
            calls.append((method, path, data))
            return [issue] if method == "GET" else {}
        environment = {"GITHUB_TOKEN": "synthetic-unit-test-token", "GITHUB_REPOSITORY": m.REPOSITORY, "GITHUB_RUN_ID": "123"}
        with patch.dict(os.environ, environment), patch.object(m, "github_api", api):
            m.notify({"status": "T14"})
            self.assertEqual(["GET"], [item[0] for item in calls])
            calls.clear()
            m.notify({"status": "T7"})
            self.assertEqual(["GET", "PATCH", "POST"], [item[0] for item in calls])

    def test_notification_recovery_only_own_marker(self):
        calls = []
        def api(method, path, token, data=None):
            calls.append((method, path, data))
            return [{"number": 42, "title": m.ISSUE_TITLE, "body": "Human unrelated issue"}] if method == "GET" else {}
        with patch.dict(os.environ, {"GITHUB_TOKEN": "synthetic-unit-test-token", "GITHUB_REPOSITORY": m.REPOSITORY,
                                     "GITHUB_RUN_ID": "123"}), patch.object(m, "github_api", api):
            m.notify({"status": "OK"})
        self.assertEqual(["GET"], [item[0] for item in calls])


class NotificationTestAcceptance(unittest.TestCase):
    def test_test_context_rejects_schedule_or_no_notify(self):
        for event, enabled in (("schedule", True), ("workflow_dispatch", False), ("push", True)):
            with self.subTest(event=event, enabled=enabled), patch.dict(os.environ, {
                    "GITHUB_EVENT_NAME": event, "P1_NOTIFICATION_TEST": "true"}):
                with self.assertRaisesRegex(m.MonitorError, "^NOTIFICATION_TEST_CONTEXT_REJECTED$"):
                    m.require_notification_test_context(enabled)

    def test_test_context_requires_explicit_true(self):
        with patch.dict(os.environ, {"GITHUB_EVENT_NAME": "workflow_dispatch", "P1_NOTIFICATION_TEST": "false"}):
            with self.assertRaisesRegex(m.MonitorError, "^NOTIFICATION_TEST_CONTEXT_REJECTED$"):
                m.require_notification_test_context(True)
        with patch.dict(os.environ, {"GITHUB_EVENT_NAME": "workflow_dispatch", "P1_NOTIFICATION_TEST": "true"}):
            m.require_notification_test_context(True)

    def test_test_report_preserves_actual_metadata_and_requires_healthy(self):
        actual = {"status": "OK", "sequence": 1010, "earliestExpiryUtc": "2026-12-17T00:00:00+00:00"}
        report = m.notification_test_report(actual)
        self.assertEqual("OK", actual["status"])
        self.assertEqual("TEST", report["status"])
        self.assertEqual("OK", report["realFeedStatus"])
        self.assertTrue(report["notificationTest"])
        self.assertEqual(actual["earliestExpiryUtc"], report["earliestExpiryUtc"])
        self.assertEqual(actual["sequence"], report["sequence"])
        for status in ("T14", "T7", "EXPIRED", "ERROR"):
            with self.subTest(status=status), self.assertRaisesRegex(
                    m.MonitorError, "^NOTIFICATION_TEST_REQUIRES_HEALTHY_METADATA$"):
                m.notification_test_report({"status": status})

    def test_test_issue_is_marked_and_normal_healthy_closes_only_marked_test(self):
        calls = []
        existing = []
        def api(method, path, token, data=None):
            calls.append((method, path, data))
            return existing if method == "GET" else {}
        environment = {"GITHUB_TOKEN": "synthetic-unit-test-token", "GITHUB_REPOSITORY": m.REPOSITORY,
                       "GITHUB_RUN_ID": "123"}
        with patch.dict(os.environ, environment), patch.object(m, "github_api", api):
            m.notify(m.notification_test_report({"status": "OK", "sequence": 1010}))
            created = calls[-1][2]
            self.assertEqual(m.TEST_ISSUE_TITLE, created["title"])
            self.assertIn("TEST notification only", created["body"])
            self.assertIn("not an expiry or security alarm", created["body"])
            self.assertIn(m.ISSUE_MARKER, created["body"])
            existing.append(dict(created, number=42))
            calls.clear()
            m.notify({"status": "OK"})
            self.assertEqual(["GET", "POST", "PATCH"], [call[0] for call in calls])
            self.assertEqual({"state": "closed"}, calls[-1][2])
            self.assertIn("Notification test complete", calls[1][2]["body"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
