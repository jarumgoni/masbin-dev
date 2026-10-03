"""
DataShield SDK Core Clients
High-performance synchronous and asynchronous clients for the DataShield Enterprise API.
"""

import time
import requests
from typing import Dict, Any, Optional, List, Union
from urllib.parse import urljoin

from .exceptions import DataShieldError, AuthenticationError, map_http_error
from .models import (
    EmailValidationResult,
    DomainAuditResult,
    IPLookupResult,
    PhoneValidationResult
)

DEFAULT_HOST = "datashield-email-verification-fraud-detection-api.p.rapidapi.com"
DEFAULT_BASE_URL = f"https://{DEFAULT_HOST}"
DEFAULT_TIMEOUT = 10.0
DEFAULT_MAX_RETRIES = 2
SDK_VERSION = "1.1.0"


class DataShieldClient:
    """
    Official Python Synchronous Client for DataShield Fraud & Verification Suite.

    Usage:
        >>> from datashield import DataShieldClient
        >>> client = DataShieldClient(api_key="YOUR_RAPIDAPI_KEY")
        >>> result = client.validate_email("user@example.com")
        >>> if result.is_disposable:
        ...     print("Blocked burner email:", result.domain)
    """

    def __init__(
        self,
        api_key: str,
        host: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
        session: Optional[requests.Session] = None
    ):
        if not api_key:
            raise AuthenticationError("API Key is required to initialize DataShieldClient")

        self.api_key = api_key
        self.host = host or DEFAULT_HOST
        self.base_url = (base_url or f"https://{self.host}").rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries

        self.session = session or requests.Session()
        self.session.headers.update({
            "X-RapidAPI-Key": self.api_key,
            "X-RapidAPI-Host": self.host,
            "User-Agent": f"DataShield-Python-SDK/{SDK_VERSION}",
            "Accept": "application/json"
        })

    def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Any] = None
    ) -> Dict[str, Any]:
        """Internal execute helper with exponential backoff retry on transient faults."""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        attempts = 0
        backoff = 0.5

        while True:
            attempts += 1
            try:
                resp = self.session.request(
                    method=method,
                    url=url,
                    params=params,
                    json=json_body,
                    timeout=self.timeout
                )

                if resp.status_code >= 400:
                    try:
                        err_payload = resp.json()
                        err_msg = err_payload.get("message") or err_payload.get("error") or resp.text
                    except Exception:
                        err_payload = {}
                        err_msg = resp.text or f"HTTP Error {resp.status_code}"

                    # Only retry on 502, 503, 504 server hiccups
                    if resp.status_code in (502, 503, 504) and attempts <= self.max_retries:
                        time.sleep(backoff)
                        backoff *= 2
                        continue

                    raise map_http_error(resp.status_code, err_msg, err_payload)

                return resp.json()

            except requests.exceptions.RequestException as e:
                if attempts <= self.max_retries:
                    time.sleep(backoff)
                    backoff *= 2
                    continue
                raise DataShieldError(f"Network transport failure connecting to DataShield API: {e}") from e

    def validate_email(self, email: str) -> EmailValidationResult:
        """
        Validate single email address format, domain MX, disposable detector, and risk verdict.

        Args:
            email (str): Target email address (e.g. 'alex@startup.io')

        Returns:
            EmailValidationResult: Structured result with dot notation attributes.
        """
        raw = self._request("GET", "/v1/email/validate", params={"email": email})
        return EmailValidationResult.from_dict(raw)

    def audit_domain(self, domain: str) -> DomainAuditResult:
        """
        Audit DNS health, mail server redundancy, SPF, and DMARC posture.

        Args:
            domain (str): Target domain name (e.g. 'company.com')

        Returns:
            DomainAuditResult: Structured domain security report.
        """
        raw = self._request("GET", "/v1/email/domain-audit", params={"domain": domain})
        return DomainAuditResult.from_dict(raw)

    def verify_phone(self, phone: str, country_code: Optional[str] = None) -> PhoneValidationResult:
        """
        Verify international phone number syntax, carrier identity, and VoIP detection.

        Args:
            phone (str): International phone string (e.g. '+14155552671')
            country_code (str, optional): Default ISO alpha-2 country code.

        Returns:
            PhoneValidationResult: Telecom carrier and fraud classification.
        """
        params = {"phone": phone}
        if country_code:
            params["country_code"] = country_code
        raw = self._request("GET", "/v1/phone/validate", params=params)
        return PhoneValidationResult.from_dict(raw)

    def lookup_ip(self, ip: str) -> IPLookupResult:
        """
        Perform IP intelligence lookup, BGP ASN routing, and datacenter proxy analysis.

        Args:
            ip (str): IPv4 or IPv6 address.

        Returns:
            IPLookupResult: Geolocation, ASN, and bot/proxy risk rating.
        """
        raw = self._request("GET", "/v1/ip/lookup", params={"ip": ip})
        return IPLookupResult.from_dict(raw)

    def clean_batch_emails(self, emails: List[str]) -> List[EmailValidationResult]:
        """
        Verify a batch of email addresses concurrently in a single API call.

        Args:
            emails (List[str]): List of up to 100 email strings.

        Returns:
            List[EmailValidationResult]: List of verified email items.
        """
        raw = self._request("POST", "/v1/email/batch-validate", json_body={"emails": emails})
        items = raw.get("data", raw.get("results", []))
        if isinstance(items, list):
            return [EmailValidationResult.from_dict(item) for item in items]
        return [EmailValidationResult.from_dict(raw)]

    def is_disposable_email(self, email: str) -> bool:
        """Fast boolean helper to identify burner / temporary email addresses."""
        res = self.validate_email(email)
        return res.is_disposable

    def is_datacenter_ip(self, ip: str) -> bool:
        """Fast boolean helper to identify datacenter proxies / VPN hops."""
        res = self.lookup_ip(ip)
        return res.is_datacenter


class AsyncDataShieldClient:
    """
    Asynchronous Python Client for DataShield Suite (asyncio-native).
    Designed for FastAPI, Tornado, and high-concurrency microservices.
    """

    def __init__(
        self,
        api_key: str,
        host: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT
    ):
        if not api_key:
            raise AuthenticationError("API Key is required to initialize AsyncDataShieldClient")
        self.api_key = api_key
        self.host = host or DEFAULT_HOST
        self.base_url = (base_url or f"https://{self.host}").rstrip("/")
        self.timeout = timeout
        self.headers = {
            "X-RapidAPI-Key": self.api_key,
            "X-RapidAPI-Host": self.host,
            "User-Agent": f"DataShield-Async-Python-SDK/{SDK_VERSION}",
            "Accept": "application/json"
        }

    async def validate_email(self, email: str) -> EmailValidationResult:
        """Asynchronously validate email address."""
        import asyncio
        import urllib.request
        import json

        loop = asyncio.get_running_loop()
        url = f"{self.base_url}/v1/email/validate?email={urllib.parse.quote(email)}"

        def _fetch():
            req = urllib.request.Request(url, headers=self.headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))

        raw = await loop.run_in_executor(None, _fetch)
        return EmailValidationResult.from_dict(raw)

    async def lookup_ip(self, ip: str) -> IPLookupResult:
        """Asynchronously perform IP intelligence lookup."""
        import asyncio
        import urllib.request
        import json

        loop = asyncio.get_running_loop()
        url = f"{self.base_url}/v1/ip/lookup?ip={urllib.parse.quote(ip)}"

        def _fetch():
            req = urllib.request.Request(url, headers=self.headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))

        raw = await loop.run_in_executor(None, _fetch)
        return IPLookupResult.from_dict(raw)
