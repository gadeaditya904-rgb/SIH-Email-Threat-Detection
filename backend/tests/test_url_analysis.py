import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from main import app
from services.url_analyzer import (
    MAX_URLS_PER_REQUEST,
    analyze_url,
    analyze_urls,
)

FIXTURES = Path(__file__).parent / "fixtures"
client = TestClient(app)


def _types(result) -> set[str]:
    return {item.type for item in result.indicators}


class UrlAnalyzerServiceTests(unittest.TestCase):
    def test_normal_https_url(self) -> None:
        result = analyze_url("https://example.com/about")
        self.assertTrue(result.parse_ok)
        self.assertEqual(result.scheme, "https")
        self.assertEqual(result.hostname, "example.com")
        self.assertIsNone(result.port)
        self.assertEqual(result.path, "/about")
        self.assertTrue(result.uses_https)
        self.assertFalse(result.is_ip_address)
        self.assertEqual(result.subdomain_count, 0)
        self.assertEqual(result.risk_level, "low")
        self.assertLess(result.score, 25)
        self.assertNotIn("no_https", _types(result))
        self.assertNotIn("ip_hostname", _types(result))

    def test_http_url_indicator(self) -> None:
        result = analyze_url("http://example.com/login")
        self.assertIn("no_https", _types(result))
        self.assertFalse(result.uses_https)
        self.assertIn("suspicious_keyword", _types(result))
        self.assertGreaterEqual(result.score, 10)

    def test_ip_address_url(self) -> None:
        result = analyze_url("http://192.0.2.10/verify")
        self.assertTrue(result.is_ip_address)
        self.assertEqual(result.hostname, "192.0.2.10")
        self.assertIn("ip_hostname", _types(result))
        self.assertIn("no_https", _types(result))
        self.assertGreaterEqual(result.score, 25)
        self.assertIn(result.risk_level, {"medium", "high", "critical"})

    def test_login_keyword_url(self) -> None:
        result = analyze_url("https://example.com/account/verify")
        self.assertIn("suspicious_keyword", _types(result))
        keyword = next(item for item in result.indicators if item.type == "suspicious_keyword")
        self.assertEqual(keyword.score, 10)
        self.assertIn("login-related", keyword.message.lower() + " contextual")

    def test_very_long_url(self) -> None:
        url = "https://example.com/" + ("a" * 200)
        result = analyze_url(url)
        self.assertIn("long_url", _types(result))
        self.assertGreaterEqual(result.score, 10)

    def test_excessive_subdomains(self) -> None:
        result = analyze_url("https://login.account.verify.security.portal.example.com/")
        self.assertGreater(result.subdomain_count, 4)
        self.assertIn("excessive_subdomains", _types(result))

    def test_punycode_hostname(self) -> None:
        result = analyze_url("https://xn--exmple-cua.com/")
        self.assertIn("punycode", _types(result))
        self.assertIn("xn--", result.hostname or "")

    def test_at_sign_in_url(self) -> None:
        result = analyze_url("https://user@example.com/inbox")
        self.assertTrue(result.parse_ok)
        self.assertIn("at_sign", _types(result))
        self.assertGreaterEqual(result.score, 15)

    def test_nonstandard_port(self) -> None:
        result = analyze_url("https://example.com:8080/status")
        self.assertEqual(result.port, 8080)
        self.assertIn("nonstandard_port", _types(result))

    def test_brand_lookalike(self) -> None:
        result = analyze_url("https://microsoft-login-example.com/account/verify")
        self.assertIn("brand_lookalike", _types(result))
        lookalike = next(item for item in result.indicators if item.type == "brand_lookalike")
        self.assertEqual(lookalike.score, 20)
        self.assertIn("analytical indicator", lookalike.message.lower())
        self.assertGreaterEqual(result.score, 20)
        official = analyze_url("https://www.microsoft.com/")
        self.assertNotIn("brand_lookalike", _types(official))

    def test_multiple_urls_overall_score_is_max(self) -> None:
        payload = analyze_urls(
            [
                "https://example.com/about",
                "http://192.0.2.10/verify",
            ]
        )
        self.assertEqual(payload.total_urls, 2)
        self.assertEqual(payload.analyzed_urls, 2)
        self.assertEqual(payload.overall_score, max(item.score for item in payload.results))
        self.assertEqual(payload.overall_risk_level, payload.results[1].risk_level)

    def test_empty_url_list(self) -> None:
        payload = analyze_urls([])
        self.assertEqual(payload.total_urls, 0)
        self.assertEqual(payload.analyzed_urls, 0)
        self.assertEqual(payload.overall_score, 0)
        self.assertEqual(payload.overall_risk_level, "low")
        self.assertEqual(payload.results, [])

    def test_malformed_url_does_not_raise(self) -> None:
        result = analyze_url("not a url")
        self.assertFalse(result.parse_ok)
        self.assertEqual(result.score, 0)
        self.assertIn("malformed_url", _types(result))
        self.assertIsNone(result.hostname)

    def test_javascript_scheme_is_malformed_for_this_module(self) -> None:
        result = analyze_url("javascript:alert(1)")
        self.assertFalse(result.parse_ok)
        self.assertIn("malformed_url", _types(result))


class UrlAnalysisAPITests(unittest.TestCase):
    def test_url_analysis_endpoint_sample_payload(self) -> None:
        response = client.post(
            "/api/email/url-analysis",
            json={
                "urls": [
                    "https://example.com/login",
                    "http://192.0.2.10/verify",
                    "https://microsoft-login-example.com/account/verify",
                ]
            },
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(
            set(payload.keys()),
            {
                "total_urls",
                "analyzed_urls",
                "overall_score",
                "overall_risk_level",
                "results",
            },
        )
        self.assertEqual(payload["total_urls"], 3)
        self.assertEqual(payload["analyzed_urls"], 3)
        self.assertEqual(len(payload["results"]), 3)
        first = payload["results"][0]
        for field in (
            "url",
            "scheme",
            "hostname",
            "port",
            "path",
            "is_ip_address",
            "uses_https",
            "subdomain_count",
            "indicators",
            "score",
            "risk_level",
        ):
            self.assertIn(field, first)
        self.assertGreaterEqual(payload["overall_score"], 25)

    def test_empty_list_api(self) -> None:
        response = client.post("/api/email/url-analysis", json={"urls": []})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["total_urls"], 0)

    def test_malformed_url_api_returns_structured_result(self) -> None:
        response = client.post(
            "/api/email/url-analysis",
            json={"urls": ["::::", "https://example.com/"]},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["total_urls"], 2)
        self.assertEqual(payload["analyzed_urls"], 1)
        self.assertFalse(payload["results"][0]["parse_ok"])
        self.assertEqual(payload["results"][0]["indicators"][0]["type"], "malformed_url")

    def test_maximum_url_validation(self) -> None:
        too_many = ["https://example.com/"] * (MAX_URLS_PER_REQUEST + 1)
        response = client.post("/api/email/url-analysis", json={"urls": too_many})
        self.assertEqual(response.status_code, 400)
        detail = response.json()["detail"]
        self.assertEqual(detail["error"], "too_many_urls")

        allowed = ["https://example.com/"] * MAX_URLS_PER_REQUEST
        ok = client.post("/api/email/url-analysis", json={"urls": allowed})
        self.assertEqual(ok.status_code, 200)
        self.assertEqual(ok.json()["total_urls"], MAX_URLS_PER_REQUEST)

    def test_urls_must_be_a_list(self) -> None:
        response = client.post("/api/email/url-analysis", json={"urls": "https://example.com"})
        self.assertEqual(response.status_code, 422)

    def test_existing_endpoints_still_work(self) -> None:
        self.assertEqual(client.get("/").status_code, 200)
        self.assertEqual(client.get("/api/health").status_code, 200)
        eml = (FIXTURES / "normal.eml").read_bytes()
        upload = client.post(
            "/api/email/upload",
            files={"file": ("normal.eml", eml, "message/rfc822")},
        )
        forensics = client.post(
            "/api/email/forensics",
            files={"file": ("normal.eml", eml, "message/rfc822")},
        )
        self.assertEqual(upload.status_code, 200)
        self.assertEqual(set(upload.json().keys()), {"filename", "headers", "body", "urls"})
        self.assertEqual(forensics.status_code, 200)
        self.assertIn("summary", forensics.json())


if __name__ == "__main__":
    unittest.main()
