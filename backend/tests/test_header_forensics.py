import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from main import app
from models.email import EmailHeaders
from services.email_parser import parse_eml_bytes
from services.header_forensics import analyze_headers, analyze_parsed_email

FIXTURES = Path(__file__).parent / "fixtures"
client = TestClient(app)


def _load(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


class HeaderForensicsServiceTests(unittest.TestCase):
    def test_normal_email_is_low_risk(self) -> None:
        parsed = parse_eml_bytes(_load("normal.eml"), "normal.eml")
        result = analyze_parsed_email(parsed)

        self.assertEqual(result.authentication.spf, "pass")
        self.assertEqual(result.authentication.dkim, "pass")
        self.assertEqual(result.authentication.dmarc, "pass")
        self.assertEqual(result.sender_analysis.from_domain, "example.com")
        self.assertEqual(result.sender_analysis.reply_to_domain, "example.com")
        self.assertEqual(result.sender_analysis.return_path_domain, "example.com")
        self.assertEqual(result.sender_analysis.message_id_domain, "example.com")
        self.assertEqual(result.summary.risk_level, "low")
        self.assertLess(result.summary.score, 25)
        suspicious_types = {
            item.type
            for item in result.indicators
            if item.type
            in {
                "spf_fail",
                "dkim_fail",
                "dmarc_fail",
                "from_reply_to_domain_mismatch",
                "from_return_path_domain_mismatch",
            }
        }
        self.assertFalse(suspicious_types)

    def test_suspicious_email_has_higher_risk_and_explainable_indicators(self) -> None:
        parsed = parse_eml_bytes(_load("suspicious.eml"), "suspicious.eml")
        result = analyze_parsed_email(parsed)

        self.assertEqual(result.authentication.spf, "fail")
        self.assertEqual(result.authentication.dkim, "fail")
        self.assertEqual(result.authentication.dmarc, "fail")
        self.assertNotEqual(
            result.sender_analysis.from_domain, result.sender_analysis.reply_to_domain
        )
        self.assertGreaterEqual(result.summary.score, 25)
        self.assertIn(result.summary.risk_level, {"medium", "high"})
        types = {item.type for item in result.indicators}
        self.assertIn("from_reply_to_domain_mismatch", types)
        self.assertIn("from_return_path_domain_mismatch", types)
        self.assertTrue({"spf_fail", "dkim_fail", "dmarc_fail"} & types)
        for indicator in result.indicators:
            self.assertTrue(indicator.type)
            self.assertTrue(indicator.severity)
            self.assertTrue(indicator.description)

    def test_multiple_received_headers_preserve_hop_order_and_ip_class(self) -> None:
        parsed = parse_eml_bytes(_load("multi_hop.eml"), "multi_hop.eml")
        result = analyze_parsed_email(parsed)

        self.assertEqual(len(result.received_chain), 3)
        self.assertEqual([hop.hop_index for hop in result.received_chain], [1, 2, 3])
        self.assertEqual(result.received_chain[0].position, "most_recent")
        self.assertEqual(result.received_chain[2].position, "earliest_observed")
        self.assertIn("10.0.0.5", result.received_chain[0].raw)
        self.assertIn("192.0.2.88", result.received_chain[2].raw)

        classifications = {
            ip.ip: ip.classification
            for hop in result.received_chain
            for ip in hop.observed_ips
        }
        self.assertEqual(classifications.get("10.0.0.5"), "private")
        self.assertEqual(classifications.get("8.8.8.8"), "public")
        self.assertNotEqual(classifications.get("192.0.2.88"), "public")
        self.assertEqual(classifications.get("192.0.2.88"), "reserved")
        self.assertEqual(classifications.get("2001:db8::88"), "reserved")

    def test_documentation_and_private_ips_are_not_public(self) -> None:
        headers = EmailHeaders.model_validate(
            {
                "from": "analyst@example.com",
                "received": [
                    "from a (192.0.2.10) by b",
                    "from a (198.51.100.10) by b",
                    "from a (203.0.113.10) by b",
                    "from a (192.168.1.10) by b",
                    "from a (10.1.2.3) by b",
                    "from a (172.16.9.9) by b",
                    "from a (127.0.0.1) by b",
                    "from a (169.254.1.1) by b",
                    "from a (8.8.8.8) by b",
                    "from a (1.1.1.1) by b",
                    "from a ([IPv6:2001:db8::10]) by b",
                    "from a ([IPv6:2001:4860:4860::8888]) by b",
                ],
            }
        )
        result = analyze_headers(headers)
        classifications = {
            ip.ip: ip.classification
            for hop in result.received_chain
            for ip in hop.observed_ips
        }

        for documentation_ip in ("192.0.2.10", "198.51.100.10", "203.0.113.10"):
            self.assertNotEqual(classifications.get(documentation_ip), "public")
            self.assertEqual(classifications.get(documentation_ip), "reserved")

        self.assertNotEqual(classifications.get("192.168.1.10"), "public")
        self.assertEqual(classifications.get("192.168.1.10"), "private")
        self.assertEqual(classifications.get("10.1.2.3"), "private")
        self.assertEqual(classifications.get("172.16.9.9"), "private")
        self.assertEqual(classifications.get("127.0.0.1"), "loopback")
        self.assertEqual(classifications.get("169.254.1.1"), "link_local")
        self.assertEqual(classifications.get("8.8.8.8"), "public")
        self.assertEqual(classifications.get("1.1.1.1"), "public")
        self.assertEqual(classifications.get("2001:db8::10"), "reserved")
        self.assertEqual(classifications.get("2001:4860:4860::8888"), "public")

    def test_missing_authentication_headers_return_unknown(self) -> None:
        parsed = parse_eml_bytes(_load("missing_auth.eml"), "missing_auth.eml")
        result = analyze_parsed_email(parsed)

        self.assertEqual(result.authentication.spf, "unknown")
        self.assertEqual(result.authentication.dkim, "unknown")
        self.assertEqual(result.authentication.dmarc, "unknown")
        self.assertEqual(result.summary.risk_level, "low")
        self.assertFalse(result.authentication.dkim_signature_present)

    def test_malformed_values_do_not_crash_analysis(self) -> None:
        headers = EmailHeaders.model_validate(
            {
                "from": "not-an-email",
                "reply-to": "<<<",
                "return-path": "",
                "message-id": "broken-id-without-domain",
                "received": ["garbage hop without structure", "from x (999.999.999.999) by y"],
                "authentication-results": ["this is not auth data"],
            }
        )
        result = analyze_headers(headers)
        self.assertIsInstance(result.summary.score, int)
        self.assertIn(result.summary.risk_level, {"low", "medium", "high"})
        self.assertEqual(len(result.received_chain), 2)


class HeaderForensicsAPITests(unittest.TestCase):
    def test_forensics_endpoint_normal_email(self) -> None:
        response = client.post(
            "/api/email/forensics",
            files={"file": ("normal.eml", _load("normal.eml"), "message/rfc822")},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["authentication"]["spf"], "pass")
        self.assertEqual(payload["summary"]["risk_level"], "low")
        self.assertIn("sender_analysis", payload)
        self.assertIn("received_chain", payload)
        self.assertIn("indicators", payload)
        self.assertIn("findings", payload)
        self.assertIn("observed_evidence", payload)

    def test_forensics_endpoint_suspicious_email(self) -> None:
        response = client.post(
            "/api/email/forensics",
            files={"file": ("suspicious.eml", _load("suspicious.eml"), "message/rfc822")},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertGreaterEqual(payload["summary"]["score"], 25)
        self.assertIn(payload["summary"]["risk_level"], ["medium", "high"])

    def test_forensics_endpoint_multi_hop(self) -> None:
        response = client.post(
            "/api/email/forensics",
            files={"file": ("multi_hop.eml", _load("multi_hop.eml"), "message/rfc822")},
        )
        self.assertEqual(response.status_code, 200)
        hops = response.json()["received_chain"]
        self.assertEqual(len(hops), 3)
        self.assertEqual(hops[0]["hop_index"], 1)
        self.assertEqual(hops[2]["hop_index"], 3)

    def test_forensics_endpoint_missing_auth(self) -> None:
        response = client.post(
            "/api/email/forensics",
            files={"file": ("missing_auth.eml", _load("missing_auth.eml"), "message/rfc822")},
        )
        self.assertEqual(response.status_code, 200)
        auth = response.json()["authentication"]
        self.assertEqual(auth["spf"], "unknown")
        self.assertEqual(auth["dkim"], "unknown")
        self.assertEqual(auth["dmarc"], "unknown")


class ExistingModule2ContractTests(unittest.TestCase):
    def test_root_and_health_unchanged(self) -> None:
        root = client.get("/")
        health = client.get("/api/health")
        self.assertEqual(root.status_code, 200)
        self.assertEqual(root.json(), {"message": "SIH Email Threat Detection API is running"})
        self.assertEqual(health.status_code, 200)
        self.assertEqual(
            health.json(),
            {"status": "healthy", "service": "Email Threat Detection Backend"},
        )

    def test_upload_response_structure_unchanged(self) -> None:
        response = client.post(
            "/api/email/upload",
            files={"file": ("normal.eml", _load("normal.eml"), "message/rfc822")},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(set(payload.keys()), {"filename", "headers", "body", "urls"})
        self.assertEqual(
            set(payload["headers"].keys()),
            {
                "from",
                "to",
                "cc",
                "subject",
                "date",
                "reply-to",
                "message-id",
                "return-path",
                "received",
                "authentication-results",
                "received-spf",
                "dkim-signature",
            },
        )
        self.assertEqual(set(payload["body"].keys()), {"plain_text", "html"})
        self.assertIsInstance(payload["urls"], list)
        self.assertNotIn("summary", payload)
        self.assertNotIn("indicators", payload)


if __name__ == "__main__":
    unittest.main()
