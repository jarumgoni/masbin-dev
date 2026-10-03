"""
DataShield SDK Exception Hierarchy
Standardized error mapping for HTTP status codes and API fault responses.
"""

from typing import Optional, Dict, Any

class DataShieldError(Exception):
    """Base exception for all DataShield SDK errors."""
    def __init__(self, message: str, status_code: Optional[int] = None, response_payload: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.response_payload = response_payload or {}

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(message={self.message!r}, status_code={self.status_code})"


class AuthenticationError(DataShieldError):
    """Raised when the RapidAPI Key is invalid, missing, or unauthorized (HTTP 401/403)."""
    pass


class RateLimitExceededError(DataShieldError):
    """Raised when the API subscription quota or per-minute rate limit is exceeded (HTTP 429)."""
    pass


class InvalidParameterError(DataShieldError):
    """Raised when request parameters fail validation or syntax checks (HTTP 400/422)."""
    pass


class ResourceNotFoundError(DataShieldError):
    """Raised when the requested endpoint or resource does not exist (HTTP 404)."""
    pass


class ServerUnavailableError(DataShieldError):
    """Raised when the DataShield edge gateway or backend experiences temporary downtime (HTTP 500/502/503/504)."""
    pass


def map_http_error(status_code: int, message: str, payload: Optional[Dict[str, Any]] = None) -> DataShieldError:
    """Helper factory to map HTTP status codes to DataShield exception subclasses."""
    if status_code in (401, 403):
        return AuthenticationError(message, status_code=status_code, response_payload=payload)
    elif status_code == 429:
        return RateLimitExceededError(message, status_code=status_code, response_payload=payload)
    elif status_code in (400, 422):
        return InvalidParameterError(message, status_code=status_code, response_payload=payload)
    elif status_code == 404:
        return ResourceNotFoundError(message, status_code=status_code, response_payload=payload)
    elif status_code >= 500:
        return ServerUnavailableError(message, status_code=status_code, response_payload=payload)
    return DataShieldError(message, status_code=status_code, response_payload=payload)
