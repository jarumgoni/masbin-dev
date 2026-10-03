"""
DataShield SDK Typed Response Models
Provides object-oriented access and dot notation for API payloads.
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field

@dataclass
class BaseResponseModel:
    """Base class for all DataShield response models, supporting dict-like access."""
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    def __getitem__(self, item: str) -> Any:
        if hasattr(self, item):
            return getattr(self, item)
        payload = self.raw.get("data", self.raw)
        if isinstance(payload, dict):
            return payload.get(item)
        return None

    def get(self, item: str, default: Any = None) -> Any:
        if hasattr(self, item):
            val = getattr(self, item)
            return val if val is not None else default
        payload = self.raw.get("data", self.raw)
        if isinstance(payload, dict):
            return payload.get(item, default)
        return default

    def to_dict(self) -> Dict[str, Any]:
        """Return the raw JSON dictionary representation."""
        return self.raw


@dataclass
class EmailValidationResult(BaseResponseModel):
    """
    Represents the parsed outcome of an email validation and fraud score query.
    """
    email: str = ""
    domain: str = ""
    is_valid_format: bool = False
    is_disposable: bool = False
    is_free_provider: bool = False
    mx_records_found: bool = False
    smtp_check: str = "unknown"
    risk_score: int = 0
    verdict: str = "ALLOW"
    reason: str = ""
    execution_time_ms: float = 0.0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EmailValidationResult":
        payload = data.get("data", data)
        return cls(
            raw=data,
            email=payload.get("email", payload.get("query", "")),
            domain=payload.get("domain", ""),
            is_valid_format=bool(payload.get("is_valid_format", payload.get("valid_format", False))),
            is_disposable=bool(payload.get("is_disposable", payload.get("disposable", False))),
            is_free_provider=bool(payload.get("is_free_provider", False)),
            mx_records_found=bool(payload.get("mx_records_found", payload.get("has_mx", False))),
            smtp_check=str(payload.get("smtp_check", "unknown")),
            risk_score=int(payload.get("risk_score", 0)),
            verdict=str(payload.get("verdict", "ALLOW" if not payload.get("is_disposable") else "REJECT")),
            reason=str(payload.get("reason", "")),
            execution_time_ms=float(data.get("execution_time_ms", 0.0))
        )


@dataclass
class DomainAuditResult(BaseResponseModel):
    """
    Represents DNS health, MX redundancy, and deliverability posture for a domain.
    """
    domain: str = ""
    has_mx: bool = False
    mx_hosts: List[str] = field(default_factory=list)
    has_spf: bool = False
    has_dmarc: bool = False
    risk_score: int = 0
    recommendations: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DomainAuditResult":
        payload = data.get("data", data)
        return cls(
            raw=data,
            domain=payload.get("domain", ""),
            has_mx=bool(payload.get("has_mx", False)),
            mx_hosts=list(payload.get("mx_hosts", [])),
            has_spf=bool(payload.get("has_spf", False)),
            has_dmarc=bool(payload.get("has_dmarc", False)),
            risk_score=int(payload.get("risk_score", 0)),
            recommendations=list(payload.get("recommendations", []))
        )


@dataclass
class IPLookupResult(BaseResponseModel):
    """
    Represents IP intelligence, BGP ASN, and datacenter proxy risk metrics.
    """
    ip: str = ""
    country: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    asn: str = ""
    org: str = ""
    is_datacenter: bool = False
    is_vpn_proxy: bool = False
    threat_level: str = "LOW"
    risk_score: int = 0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IPLookupResult":
        payload = data.get("data", data)
        return cls(
            raw=data,
            ip=payload.get("ip", ""),
            country=payload.get("country", ""),
            country_code=payload.get("country_code", ""),
            region=payload.get("region", ""),
            city=payload.get("city", ""),
            asn=payload.get("asn", ""),
            org=payload.get("org", payload.get("isp", "")),
            is_datacenter=bool(payload.get("is_datacenter", payload.get("is_datacenter_proxy", False))),
            is_vpn_proxy=bool(payload.get("is_vpn_proxy", False)),
            threat_level=str(payload.get("threat_level", "LOW")),
            risk_score=int(payload.get("risk_score", 0))
        )


@dataclass
class PhoneValidationResult(BaseResponseModel):
    """
    Represents international phone verification, telco carrier, and VoIP fraud flags.
    """
    phone: str = ""
    is_valid: bool = False
    country_code: str = ""
    carrier: str = ""
    line_type: str = "mobile"
    is_voip: bool = False
    risk_score: int = 0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PhoneValidationResult":
        payload = data.get("data", data)
        return cls(
            raw=data,
            phone=payload.get("phone", ""),
            is_valid=bool(payload.get("is_valid", payload.get("valid", False))),
            country_code=payload.get("country_code", ""),
            carrier=payload.get("carrier", "Unknown"),
            line_type=payload.get("line_type", "mobile"),
            is_voip=bool(payload.get("is_voip", False)),
            risk_score=int(payload.get("risk_score", 0))
        )
