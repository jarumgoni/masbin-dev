"""
DataShield Python SDK - Enterprise Email Hygiene, Fraud Detection, and Threat Intelligence.
"""

from .client import DataShieldClient, AsyncDataShieldClient
from .models import (
    EmailValidationResult,
    DomainAuditResult,
    IPLookupResult,
    PhoneValidationResult,
    BaseResponseModel
)
from .exceptions import (
    DataShieldError,
    AuthenticationError,
    RateLimitExceededError,
    InvalidParameterError,
    ResourceNotFoundError,
    ServerUnavailableError
)

__version__ = "1.1.0"
__author__ = "masbin"

__all__ = [
    "DataShieldClient",
    "AsyncDataShieldClient",
    "EmailValidationResult",
    "DomainAuditResult",
    "IPLookupResult",
    "PhoneValidationResult",
    "BaseResponseModel",
    "DataShieldError",
    "AuthenticationError",
    "RateLimitExceededError",
    "InvalidParameterError",
    "ResourceNotFoundError",
    "ServerUnavailableError"
]
