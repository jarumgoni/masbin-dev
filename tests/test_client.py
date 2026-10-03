"""
Unit tests for DataShield SDK
"""

import unittest
from unittest.mock import MagicMock, patch
from datashield import (
    DataShieldClient,
    EmailValidationResult,
    DomainAuditResult,
    IPLookupResult,
    PhoneValidationResult,
    AuthenticationError,
    RateLimitExceededError,
    DataShieldError
)

class TestDataShieldClient(unittest.TestCase):

    def test_missing_api_key_raises_error(self):
        with self.assertRaises(AuthenticationError):
            DataShieldClient(api_key="")

    def test_email_validation_model(self):
        mock_payload = {
            "status": "success",
            "execution_time_ms": 12.4,
            "data": {
                "email": "malicious@tempmail.com",
                "domain": "tempmail.com",
                "is_valid_format": True,
                "is_disposable": True,
                "is_free_provider": False,
                "mx_records_found": True,
                "smtp_check": "valid",
                "risk_score": 95,
                "verdict": "REJECT",
                "reason": "Disposable / burner inbox domain detected"
            }
        }
        res = EmailValidationResult.from_dict(mock_payload)
        self.assertEqual(res.email, "malicious@tempmail.com")
        self.assertEqual(res.domain, "tempmail.com")
        self.assertTrue(res.is_disposable)
        self.assertEqual(res.verdict, "REJECT")
        self.assertEqual(res.risk_score, 95)
        # Test dict access
        self.assertEqual(res["risk_score"], 95)

    def test_ip_lookup_model(self):
        mock_payload = {
            "status": "success",
            "data": {
                "ip": "8.8.8.8",
                "country": "United States",
                "country_code": "US",
                "region": "California",
                "city": "Mountain View",
                "asn": "AS15169",
                "org": "Google LLC",
                "is_datacenter": True,
                "is_vpn_proxy": False,
                "threat_level": "LOW",
                "risk_score": 10
            }
        }
        res = IPLookupResult.from_dict(mock_payload)
        self.assertEqual(res.ip, "8.8.8.8")
        self.assertEqual(res.country_code, "US")
        self.assertTrue(res.is_datacenter)
        self.assertFalse(res.is_vpn_proxy)

    @patch("requests.Session.request")
    def test_client_validate_email_success(self, mock_request):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "success",
            "data": {
                "email": "ceo@stripe.com",
                "domain": "stripe.com",
                "is_valid_format": True,
                "is_disposable": False,
                "risk_score": 0,
                "verdict": "ALLOW"
            }
        }
        mock_request.return_value = mock_resp

        client = DataShieldClient(api_key="test_key_xyz")
        res = client.validate_email("ceo@stripe.com")

        self.assertEqual(res.verdict, "ALLOW")
        self.assertFalse(res.is_disposable)
        mock_request.assert_called_once()

    @patch("requests.Session.request")
    def test_client_rate_limit_error(self, mock_request):
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_resp.json.return_value = {"message": "You have exceeded the RATE limit of 60 requests per minute"}
        mock_request.return_value = mock_resp

        client = DataShieldClient(api_key="test_key_xyz", max_retries=0)
        with self.assertRaises(RateLimitExceededError):
            client.validate_email("test@example.com")


if __name__ == "__main__":
    unittest.main()
