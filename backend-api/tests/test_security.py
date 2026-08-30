import asyncio
import os
import sys
import tempfile
import threading
import unittest
import json
import io
import wave
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, patch


BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))
TEST_DB = tempfile.NamedTemporaryFile(prefix="cyberkavach-test-", suffix=".db", delete=False)
TEST_DB.close()
os.environ["CYBERKAVACH_DB_FILE"] = TEST_DB.name
# ASGI tests use Starlette's conventional internal host. Keep this test-only
# setting independent from the developer's production/local .env host allowlist.
os.environ["CYBERKAVACH_ALLOWED_HOSTS"] = "127.0.0.1,localhost,testserver"
os.environ["CYBERKAVACH_ALLOWED_ORIGIN_REGEX"] = r"^(?:http://(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]):[0-9]{1,5}|chrome-extension://[a-p]{32})$"

import main  # noqa: E402
from fastapi import HTTPException, UploadFile  # noqa: E402
from scanner import TitanScanner, scan_website_logic  # noqa: E402
from apk_shield import TitanAPKScanner  # noqa: E402
from security import normalize_api_key, safe_get, validate_public_url, validate_upload  # noqa: E402
from shadow_scout import analyze_shadow_query  # noqa: E402
from ml_url_model import FEATURE_NAMES, extract_url_features, predict_phishing_probability  # noqa: E402
from prepare_phiusiil_dataset import cyberkavach_label  # noqa: E402
from satark_engine import SatarkForensicsEngine  # noqa: E402
from PIL import Image  # noqa: E402


class SecurityValidationTests(unittest.TestCase):
    def test_url_model_features_are_stable_and_complete(self):
        features = extract_url_features("https://sbi-kyc-update.example/login?a=1")
        self.assertEqual(len(features), len(FEATURE_NAMES))
        self.assertEqual(features[7], 0.0)
        self.assertGreater(features[-1], 0)

    def test_url_model_is_off_until_explicitly_enabled(self):
        previous = os.environ.pop("CYBERKAVACH_ENABLE_URL_MODEL", None)
        try:
            self.assertIsNone(predict_phishing_probability("https://example.com/"))
        finally:
            if previous is not None:
                os.environ["CYBERKAVACH_ENABLE_URL_MODEL"] = previous

    def test_phiusiil_labels_are_mapped_in_the_correct_direction(self):
        self.assertEqual(cyberkavach_label("0"), 1)  # PhiUSIIL phishing
        self.assertEqual(cyberkavach_label("1"), 0)  # PhiUSIIL legitimate
        self.assertIsNone(cyberkavach_label("unknown"))
    @staticmethod
    def upload(name, data, content_type):
        file_object = tempfile.SpooledTemporaryFile()
        file_object.write(data)
        file_object.seek(0)
        return UploadFile(filename=name, file=file_object, headers={"content-type": content_type})

    def test_api_key_format_rejects_injection_and_accepts_local_session_key(self):
        local_key = "CK-LOCAL-" + "A" * 32
        self.assertEqual(normalize_api_key(local_key), local_key)
        with self.assertRaises(HTTPException):
            normalize_api_key("' OR 1=1 --")

    @patch("security.socket.getaddrinfo")
    def test_ssrf_blocks_private_ipv4(self, resolver):
        resolver.return_value = [(2, 1, 6, "", ("127.0.0.1", 80))]
        with self.assertRaisesRegex(ValueError, "blocked"):
            validate_public_url("http://attacker.example")

    @patch("security.socket.getaddrinfo")
    def test_ssrf_blocks_cloud_metadata(self, resolver):
        resolver.return_value = [(2, 1, 6, "", ("169.254.169.254", 80))]
        with self.assertRaisesRegex(ValueError, "blocked"):
            validate_public_url("http://metadata.example/latest/meta-data")

    @patch("security.socket.getaddrinfo")
    def test_public_https_url_is_normalized(self, resolver):
        resolver.return_value = [(2, 1, 6, "", ("93.184.216.34", 443))]
        self.assertEqual(validate_public_url("https://Example.com/a#fragment"), "https://example.com/a")

    @patch("security.validate_public_url", return_value="https://example.com/")
    @patch("security.requests.Session")
    def test_dns_rebinding_private_peer_is_blocked(self, session_class, _validator):
        class Socket:
            @staticmethod
            def getpeername():
                return ("10.0.0.8", 443)

        class Response:
            status_code = 200
            raw = type("Raw", (), {"_connection": type("Connection", (), {"sock": Socket()})()})()

            @staticmethod
            def close():
                return None

        session_class.return_value.get.return_value = Response()
        with self.assertRaisesRegex(ValueError, "blocked"):
            safe_get("https://example.com", headers={}, timeout=1, max_bytes=100)

    def test_upload_size_and_extension_are_enforced(self):
        upload = self.upload("payload.exe", b"x", "application/octet-stream")
        with self.assertRaises(HTTPException) as context:
            asyncio.run(validate_upload(upload, max_bytes=10, allowed_extensions={".apk"}, allowed_content_types={"application/octet-stream"}))
        self.assertEqual(context.exception.status_code, 415)
        upload.file.close()

        oversized = self.upload("test.apk", b"x" * 11, "application/octet-stream")
        with self.assertRaises(HTTPException) as context:
            asyncio.run(validate_upload(oversized, max_bytes=10, allowed_extensions={".apk"}, allowed_content_types={"application/octet-stream"}))
        self.assertEqual(context.exception.status_code, 413)
        oversized.file.close()


class BackendBehaviorTests(unittest.TestCase):
    def setUp(self):
        conn = main.get_db_connection()
        conn.execute("DELETE FROM scan_logs")
        conn.execute("DELETE FROM users")
        conn.commit()
        conn.close()

    def test_database_stores_only_key_hash(self):
        raw_key = "CK-LOCAL-" + "B" * 32
        user = main.verify_and_sync_user(raw_key)
        self.assertTrue(user["api_key"].startswith("sha256$"))
        conn = main.get_db_connection()
        stored = conn.execute("SELECT api_key FROM users").fetchone()["api_key"]
        conn.close()
        self.assertNotEqual(stored, raw_key)

    def test_unsupported_key_is_rejected(self):
        with self.assertRaises(HTTPException) as context:
            main.verify_and_sync_user("CK-PRO-" + "A" * 24)
        self.assertEqual(context.exception.status_code, 401)

    def test_spoofed_apk_is_rejected_before_analysis(self):
        file_object = tempfile.SpooledTemporaryFile()
        file_object.write(b"this is not a zip archive")
        file_object.seek(0)
        upload = UploadFile(filename="fake.apk", file=file_object, headers={"content-type": "application/octet-stream"})
        key = "CK-LOCAL-" + "F" * 32
        with self.assertRaises(HTTPException) as context:
            asyncio.run(main.scan_apk_endpoint(upload, key))
        file_object.close()
        self.assertEqual(context.exception.status_code, 415)
        user = main.verify_and_sync_user(key)
        self.assertEqual(user["ai_used"], 0)

    @patch("main.run_engine", new_callable=AsyncMock, return_value={"status": "SAFE", "risk_score": 0, "ai_analysis": []})
    def test_extension_background_scan_returns_result_without_quota_data(self, _engine):
        raw_key = "CK-LOCAL-" + "A" * 32
        result = asyncio.run(main.scan_url_endpoint(
            main.UrlRequest(url="https://example.com"), raw_key, "extension-background"
        ))
        self.assertEqual(result["status"], "SAFE")
        self.assertNotIn("quota_charged", result)

    def test_clear_history_uses_normalized_owner(self):
        raw_key = "CK-LOCAL-" + "D" * 32
        user = main.verify_and_sync_user(raw_key)
        main.log_scan(user["api_key"], "https://example.com", "SAFE", 0, "test", [])
        asyncio.run(main.clear_history(raw_key))
        conn = main.get_db_connection()
        count = conn.execute("SELECT COUNT(*) AS count FROM scan_logs").fetchone()["count"]
        conn.close()
        self.assertEqual(count, 0)

    def test_shadow_scout_upi_is_deterministic(self):
        first = analyze_shadow_query("normaluser@oksbi", "upi")
        second = analyze_shadow_query("normaluser@oksbi", "upi")
        self.assertEqual(first["status"], second["status"])
        self.assertEqual(first["risk_score"], second["risk_score"])

    def test_normal_jpeg_without_exif_is_not_marked_suspicious(self):
        image = Image.new("RGB", (80, 80), color=(120, 160, 200))
        payload = io.BytesIO()
        image.save(payload, "JPEG", quality=85)
        report = SatarkForensicsEngine(payload.getvalue(), "shared-photo.jpg").scan()
        self.assertEqual(report["verdict"], "NO STRONG WARNING")
        self.assertLess(report["risk_score"], 40)
        self.assertTrue(any(section["title"] == "File details" for section in report["details"]))
        self.assertTrue(any(section["title"] == "Image properties" for section in report["details"]))

    def test_normal_google_search_query_is_not_a_long_url_warning(self):
        scanner = TitanScanner(
            "https://www.google.com/search?q=open+phishing&sourceid=chrome&long_tracking_value=" + "x" * 200
        )
        scanner.analyze_lexical_features()
        self.assertTrue(scanner.is_normal_search_results_page())
        self.assertFalse(any("Suspiciously long URL" in item for item in scanner.ai_analysis))
        self.assertEqual(scanner.risk_score, 0)

    def test_satark_pdf_report_masks_sensitive_indicators(self):
        payload = (
            b"%PDF-1.4\n/Type /Page\n/Creator (Canva)\n/Producer (Test)\n"
            b"https://example.com/login contact@example.com +91 9876543210 helpdesk@ybl\n"
        )
        report = SatarkForensicsEngine(payload, "notice.pdf", "pdf").scan()
        sections = {section["title"]: section["items"] for section in report["details"]}
        values = {item["label"]: item["value"] for item in sections["Extracted indicators"]}
        self.assertEqual(values["Phone numbers"], "+91 98******10")
        self.assertIn("he******@ybl", values["UPI IDs"])

    def test_satark_wav_report_includes_audio_properties(self):
        payload = io.BytesIO()
        with wave.open(payload, "wb") as audio:
            audio.setnchannels(1)
            audio.setsampwidth(2)
            audio.setframerate(8000)
            audio.writeframes(b"\x00\x00" * 8000)
        report = SatarkForensicsEngine(payload.getvalue(), "voice.wav", "audio").scan()
        sections = {section["title"]: section["items"] for section in report["details"]}
        values = {item["label"]: item["value"] for item in sections["Audio properties"]}
        self.assertEqual(values["Duration"], "1.0 seconds")
        self.assertEqual(values["Sample rate"], "8000 Hz")

    def test_satark_formats_exif_gps_coordinates(self):
        gps = {
            1: "N", 2: ((12, 1), (30, 1), (0, 1)),
            3: "E", 4: ((77, 1), (15, 1), (0, 1)),
        }
        self.assertEqual(SatarkForensicsEngine._format_gps(gps), "12.500000, 77.250000")

    @patch("shadow_scout.ShadowScoutEngine.check_password_kanonymity")
    def test_password_target_never_leaks_characters_in_mask(self, _lookup):
        result = analyze_shadow_query("VerySecretPassword!", "password")
        self.assertEqual(result["masked_target"], "***")

    def test_scanner_executor_path_no_longer_crashes(self):
        scanner = TitanScanner("https://example.com/")
        with patch.object(scanner, "analyze_whois"), patch.object(scanner, "analyze_dom"), patch.object(scanner, "analyze_reputation"):
            result = scanner.generate_report()
        self.assertIn(result["status"], {"SAFE", "SUSPICIOUS", "MALWARE DETECTED"})
        self.assertIn(result["confidence_level"], {"LOW", "MEDIUM", "HIGH"})
        self.assertIn("disclaimer", result)
        self.assertTrue(any(section["title"] == "URL details" for section in result["details"]))
        self.assertTrue(any(section["title"] == "Page checks" for section in result["details"]))

    def test_dashboard_returns_structured_url_scan_details(self):
        raw_key = "CK-LOCAL-" + "E" * 32
        user = main.verify_and_sync_user(raw_key)
        main.log_scan(
            user["api_key"], "https://example.com", "SAFE", 0, "Titan Web Scanner", ["[Info] Test"],
            [{"title": "URL details", "items": [{"label": "Host", "value": "example.com"}]}],
        )
        # Feature-page scans are deliberately excluded from the URL dashboard.
        main.log_scan(user["api_key"], "photo.jpg", "SAFE", 0, "File scan (IMAGE)", [])
        main.log_scan(user["api_key"], "sample.apk", "CLEAN", 0, "APK scan", [])
        main.log_scan(user["api_key"], "[UPI] ***", "SAFE", 0, "Privacy check", [])
        payload = asyncio.run(main.get_dashboard_data(raw_key))
        self.assertEqual(len(payload["logs"]), 1)
        self.assertEqual(payload["logs"][0]["method"], "Titan Web Scanner")
        self.assertEqual(payload["logs"][0]["details"][0]["title"], "URL details")
        self.assertEqual(payload["logs"][0]["details"][0]["items"][0]["value"], "example.com")

    def test_official_bank_login_is_not_a_brand_spoof(self):
        scanner = TitanScanner("https://www.sbi.co.in/login")
        scanner.analyze_lexical_features()
        self.assertLess(scanner.risk_score, 30)
        self.assertFalse(any("not on the official domain" in item for item in scanner.ai_analysis))

    def test_brand_lookalike_with_login_is_flagged(self):
        scanner = TitanScanner("https://sbi-kyc-login.example/verify")
        scanner.analyze_lexical_features()
        self.assertGreaterEqual(scanner.risk_score, 30)

    def test_scanner_flags_hidden_destination_and_risky_download_patterns(self):
        scanner = TitanScanner("https://bit.ly/paytm-kyc-update.apk?next=https%3A%2F%2Fevil.example")
        scanner.analyze_lexical_features()
        joined = " ".join(scanner.ai_analysis)
        self.assertIn("Shortened link hides", joined)
        self.assertIn("encoded separators", joined)
        self.assertIn("redirect parameter", joined)
        self.assertIn("risky download", joined)
        self.assertGreaterEqual(scanner.risk_score, 50)

    def test_apk_report_includes_structured_file_and_code_details(self):
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"android.permission.RECEIVE_SMS android.permission.CAMERA")
            archive.writestr("classes.dex", b"Landroid/telephony/SmsManager;->sendTextMessage api.telegram.org 8.8.8.8")
            archive.writestr("META-INF/CERT.RSA", b"test certificate")
            archive.writestr("lib/arm64-v8a/libsample.so", b"native code")
        report = TitanAPKScanner(payload.getvalue(), "sample.apk").scan()
        sections = {section["title"]: section["items"] for section in report["details"]}
        file_values = {item["label"]: item["value"] for item in sections["File details"]}
        structure_values = {item["label"]: item["value"] for item in sections["APK structure"]}
        permission_values = {item["label"]: item["value"] for item in sections["Permissions"]}
        self.assertEqual(file_values["File name"], "sample.apk")
        self.assertEqual(structure_values["Manifest"], "Found")
        self.assertIn("arm64-v8a", structure_values["Native code"])
        self.assertIn("RECEIVE_SMS", permission_values["High-risk permissions"])

    @patch("scanner.safe_get")
    def test_dom_review_reports_risky_forms_downloads_and_embeds(self, safe_get_mock):
        class Response:
            url = "https://login.example/"
            encoding = "utf-8"
            _cyberkavach_redirect_count = 0

        html = b'''<html><head><title>Sign in</title></head><body oncontextmenu="return false">
            <form method="get" action="https://collect.example/submit"><input type="password"></form>
            <iframe hidden src="https://embed.example/"></iframe>
            <script src="https://cdn.example/app.js"></script><script>window.open('popup')</script>
            <a href="https://files.example/update.apk">Download update</a><a href="mailto:help@example.com">Mail</a>
        </body></html>'''
        safe_get_mock.return_value = (Response(), html)
        scanner = TitanScanner("https://login.example/")
        scanner.analyze_dom()
        page = scanner.page_summary
        self.assertEqual(page["cross_domain_forms"], 1)
        self.assertGreaterEqual(page["risky_form_actions"], 1)
        self.assertEqual(page["hidden_iframes"], 1)
        self.assertEqual(page["download_links"], 1)
        self.assertEqual(page["mail_links"], 1)
        self.assertEqual(page["popup_scripts"], 1)
        self.assertGreaterEqual(scanner.risk_score, 60)

    @patch("scanner.lookup_url_reputation", return_value={
        "checked": True, "hit": True, "provider": "test", "categories": ["SOCIAL_ENGINEERING"]
    })
    def test_reputation_hit_is_high_risk_evidence(self, _reputation):
        scanner = TitanScanner("https://example.com/")
        scanner.analyze_reputation()
        self.assertGreaterEqual(scanner.risk_score, 100)

    @patch("scanner.validate_public_url", side_effect=ValueError("blocked"))
    def test_scanner_returns_rejected_for_blocked_target(self, _validator):
        result = scan_website_logic("http://127.0.0.1")
        self.assertEqual(result["status"], "REJECTED")


class AsgiIntegrationTests(unittest.TestCase):
    @staticmethod
    def request(method, path, *, headers=None, body=b""):
        sent = []
        delivered = False

        async def receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.disconnect"}

        async def send(message):
            sent.append(message)

        request_headers = {"host": "testserver", **(headers or {})}
        encoded_headers = [(key.lower().encode(), value.encode()) for key, value in request_headers.items()]
        scope = {
            "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
            "method": method, "scheme": "http", "path": path, "raw_path": path.encode(),
            "query_string": b"", "headers": encoded_headers,
            "client": ("203.0.113.10", 12345), "server": ("testserver", 80), "root_path": "",
        }
        asyncio.run(main.app(scope, receive, send))
        start = next(item for item in sent if item["type"] == "http.response.start")
        response_body = b"".join(item.get("body", b"") for item in sent if item["type"] == "http.response.body")
        return start["status"], dict(start["headers"]), response_body

    def test_health_has_security_headers(self):
        status, headers, body = self.request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(headers[b"x-content-type-options"], b"nosniff")
        self.assertEqual(json.loads(body), {"status": "ok"})

    def test_disallowed_cors_origin_gets_no_allow_origin_header(self):
        status, headers, _ = self.request("GET", "/health", headers={"origin": "https://evil.example"})
        self.assertEqual(status, 200)
        self.assertNotIn(b"access-control-allow-origin", headers)

    def test_loopback_cors_origin_is_allowed_on_a_nonstandard_dev_port(self):
        status, headers, _ = self.request("OPTIONS", "/user-status", headers={
            "origin": "http://[::1]:5173", "access-control-request-method": "GET"
        })
        self.assertEqual(status, 200)
        self.assertEqual(headers[b"access-control-allow-origin"], b"http://[::1]:5173")

    def test_zero_address_preview_origin_is_allowed_in_development(self):
        origin = "http://0.0.0.0:5500"
        status, headers, _ = self.request("OPTIONS", "/scan", headers={
            "origin": origin, "access-control-request-method": "POST",
            "access-control-request-headers": "content-type,x-api-key",
        })
        self.assertEqual(status, 200)
        self.assertEqual(headers[b"access-control-allow-origin"], origin.encode())

    def test_local_chrome_extension_origin_is_allowed_in_development(self):
        origin = "chrome-extension://abcdefghijklmnopabcdefghijklmnop"
        status, headers, _ = self.request("OPTIONS", "/scan", headers={
            "origin": origin, "access-control-request-method": "POST",
            "access-control-request-headers": "content-type,x-api-key,x-scan-mode",
        })
        self.assertEqual(status, 200)
        self.assertEqual(headers[b"access-control-allow-origin"], origin.encode())

    def test_untrusted_host_is_rejected(self):
        status, _, _ = self.request("GET", "/health", headers={"host": "evil.example"})
        self.assertEqual(status, 400)

    def test_invalid_key_rejected_through_http_stack(self):
        status, _, _ = self.request("GET", "/user-status", headers={"x-api-key": "bad key"})
        self.assertEqual(status, 401)

    def test_private_target_rejected_through_http_stack(self):
        payload = json.dumps({"url": "http://127.0.0.1/admin"}).encode()
        status, _, body = self.request(
            "POST", "/scan",
            headers={"content-type": "application/json", "x-api-key": "CK-LOCAL-" + "E" * 32},
            body=payload,
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["status"], "REJECTED")

    def test_overlong_scan_url_is_rejected_with_validation_error(self):
        payload = json.dumps({"url": "https://example.com/" + ("a" * 2100)}).encode()
        status, _, _ = self.request(
            "POST", "/scan", headers={"content-type": "application/json", "x-api-key": "CK-LOCAL-" + "B" * 32}, body=payload
        )
        self.assertEqual(status, 422)

    def test_scan_feedback_is_stored(self):
        payload = json.dumps({
            "target": "https://example.com/", "feedback_type": "false_positive", "comment": "Known-safe test site"
        }).encode()
        key = "CK-LOCAL-" + "C" * 32
        status, _, body = self.request(
            "POST", "/scan-feedback", headers={"content-type": "application/json", "x-api-key": key}, body=payload
        )
        self.assertEqual(status, 200)
        self.assertIn("recorded", json.loads(body)["message"])
        user = main.verify_and_sync_user(key)
        conn = main.get_db_connection()
        count = conn.execute("SELECT COUNT(*) AS count FROM scan_feedback WHERE api_key=?", (user["api_key"],)).fetchone()["count"]
        conn.close()
        self.assertEqual(count, 1)

    @patch.object(main.rate_limiter, "allow", return_value=False)
    def test_rate_limit_returns_json_429(self, _allow):
        status, headers, body = self.request("GET", "/health")
        self.assertEqual(status, 429)
        self.assertEqual(json.loads(body)["detail"], "Too many requests. Try again shortly.")
        self.assertEqual(headers[b"content-type"], b"application/json")


if __name__ == "__main__":
    unittest.main()
