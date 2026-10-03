import requests
from typing import Dict, Any, Optional

class DataShieldClient:
    """
    Official Python Client for DataShield APIs hosted on RapidAPI Hub.
    """
    DEFAULT_HOST = "datashield-email-verification-fraud-detection-api.p.rapidapi.com"
    BASE_URL = f"https://{DEFAULT_HOST}"

    def __init__(self, api_key: str, host: Optional[str] = None):
        if not api_key:
            raise ValueError("API Key is required to initialize DataShieldClient")
        self.api_key = api_key
        self.host = host or self.DEFAULT_HOST
        self.session = requests.Session()
        self.session.headers.update({
            "X-RapidAPI-Key": self.api_key,
            "X-RapidAPI-Host": self.host,
            "User-Agent": "DataShield-Python-SDK/1.0.0"
        })

    def validate_email(self, email: str) -> Dict[str, Any]:
        """
        Validate email syntax, verify MX records, detect disposable domains, and get risk score.
        """
        url = f"{self.BASE_URL}/v1/email/validate"
        resp = self.session.get(url, params={"email": email}, timeout=10)
        resp.raise_for_status()
        return resp.json()

    def audit_domain(self, domain: str) -> Dict[str, Any]:
        """
        Audit domain DNS records, MX redundancy, and general security posture.
        """
        url = f"{self.BASE_URL}/v1/email/domain-audit"
        resp = self.session.get(url, params={"domain": domain}, timeout=10)
        resp.raise_for_status()
        return resp.json()

    def verify_phone(self, phone: str, country_code: Optional[str] = None) -> Dict[str, Any]:
        """
        Verify international phone number, carrier lookup, and fraud risk score.
        """
        url = f"{self.BASE_URL}/v1/phone/validate"
        params = {"phone": phone}
        if country_code:
            params["country_code"] = country_code
        resp = self.session.get(url, params=params, timeout=10)
        resp.raise_for_status()
        return resp.json()

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """
        Lookup IP geolocation, datacenter classification, and threat assessment.
        """
        url = f"{self.BASE_URL}/v1/ip/lookup"
        resp = self.session.get(url, params={"ip": ip}, timeout=10)
        resp.raise_for_status()
        return resp.json()

    def is_proxy_or_datacenter(self, ip: str) -> bool:
        """
        Fast boolean check if an IP belongs to a datacenter proxy or VPN provider.
        """
        url = f"{self.BASE_URL}/v1/ip/check-proxy"
        resp = self.session.get(url, params={"ip": ip}, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        return data.get("is_datacenter_proxy", False)
