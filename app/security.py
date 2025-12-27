"""Security utilities for credential handling and secret masking"""

import re
from typing import Any, Dict, Union


# List of field names that should be masked
SENSITIVE_FIELDS = {
    "password",
    "passwd",
    "pwd",
    "secret",
    "api_key",
    "apikey",
    "token",
    "auth",
    "credential",
    "private_key",
    "sftp_password",
}


def mask_sensitive_value(value: str, show_length: bool = True) -> str:
    """
    Mask a sensitive value for safe logging.

    Args:
        value: The sensitive value to mask
        show_length: Whether to include the length in the masked output

    Returns:
        Masked string like "***" or "*** (8 chars)"
    """
    if not value:
        return "*** (empty)"

    if show_length:
        return f"*** ({len(value)} chars)"
    else:
        return "***"


def mask_dict(data: Dict[str, Any], sensitive_keys: set = None) -> Dict[str, Any]:
    """
    Recursively mask sensitive values in a dictionary.

    Args:
        data: Dictionary to mask
        sensitive_keys: Set of key names to mask (defaults to SENSITIVE_FIELDS)

    Returns:
        New dictionary with sensitive values masked
    """
    if sensitive_keys is None:
        sensitive_keys = SENSITIVE_FIELDS

    masked = {}

    for key, value in data.items():
        key_lower = key.lower()

        # Check if this key should be masked
        if any(sensitive in key_lower for sensitive in sensitive_keys):
            masked[key] = mask_sensitive_value(str(value) if value else "")
        elif isinstance(value, dict):
            # Recursively mask nested dictionaries
            masked[key] = mask_dict(value, sensitive_keys)
        elif isinstance(value, list):
            # Mask items in lists
            masked[key] = [
                mask_dict(item, sensitive_keys) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            masked[key] = value

    return masked


def mask_url(url: str) -> str:
    """
    Mask credentials in URLs (e.g., sftp://user:pass@host/path).

    Args:
        url: URL that may contain credentials

    Returns:
        URL with credentials masked
    """
    # Pattern: protocol://user:password@host
    pattern = r'(://[^:]+:)[^@]+(@)'
    return re.sub(pattern, r'\1***\2', url)


def safe_repr(obj: Any, max_length: int = 100) -> str:
    """
    Create a safe string representation of an object for logging.

    Truncates long strings and masks objects that might contain credentials.

    Args:
        obj: Object to represent
        max_length: Maximum length for string representation

    Returns:
        Safe string representation
    """
    # For Pydantic models, check if they have passwords
    if hasattr(obj, 'model_dump'):
        # It's a Pydantic model
        class_name = obj.__class__.__name__

        # Check if this model type typically contains passwords
        if 'password' in str(obj.__class__.__dict__).lower():
            return f"<{class_name} (contains credentials)>"

        # Otherwise show truncated repr
        repr_str = repr(obj)
        if len(repr_str) > max_length:
            return f"{repr_str[:max_length]}..."
        return repr_str

    # For regular objects
    repr_str = repr(obj)
    if len(repr_str) > max_length:
        return f"{repr_str[:max_length]}..."
    return repr_str


class ConnectionRetryLimiter:
    """
    Limits retry attempts for connections to prevent brute force attacks.

    Tracks failed connection attempts per host and enforces maximum retry limits.
    """

    def __init__(self, max_retries: int = 3, lockout_duration: int = 300):
        """
        Initialize the retry limiter.

        Args:
            max_retries: Maximum number of failed attempts before lockout
            lockout_duration: Lockout duration in seconds (not implemented yet)
        """
        self.max_retries = max_retries
        self.lockout_duration = lockout_duration
        self._attempts: Dict[str, int] = {}

    def check_and_increment(self, host: str) -> bool:
        """
        Check if connection is allowed and increment attempt counter.

        Args:
            host: Hostname/IP to check

        Returns:
            True if connection is allowed, False if rate limited
        """
        current_attempts = self._attempts.get(host, 0)

        if current_attempts >= self.max_retries:
            return False

        self._attempts[host] = current_attempts + 1
        return True

    def reset(self, host: str):
        """Reset attempt counter for a host (on successful connection)"""
        if host in self._attempts:
            del self._attempts[host]

    def get_attempts(self, host: str) -> int:
        """Get current attempt count for a host"""
        return self._attempts.get(host, 0)


# Global retry limiter instance (configurable via settings)
_retry_limiter: Union[ConnectionRetryLimiter, None] = None


def get_retry_limiter() -> ConnectionRetryLimiter:
    """Get or create the global retry limiter instance"""
    global _retry_limiter
    if _retry_limiter is None:
        _retry_limiter = ConnectionRetryLimiter(max_retries=5)
    return _retry_limiter


def validate_no_secrets_in_response(response_data: Dict[str, Any]) -> None:
    """
    Validate that a response doesn't contain any sensitive fields.

    Raises ValueError if sensitive data is found.

    Args:
        response_data: Response dictionary to validate

    Raises:
        ValueError: If sensitive fields are found in response
    """
    def check_dict(d: Dict[str, Any], path: str = ""):
        for key, value in d.items():
            current_path = f"{path}.{key}" if path else key
            key_lower = key.lower()

            # Check if this is a sensitive field
            if any(sensitive in key_lower for sensitive in SENSITIVE_FIELDS):
                # Allow if explicitly None or empty
                if value is not None and value != "":
                    raise ValueError(
                        f"Response contains sensitive field: {current_path}"
                    )

            # Recursively check nested dicts
            if isinstance(value, dict):
                check_dict(value, current_path)
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        check_dict(item, f"{current_path}[{i}]")

    check_dict(response_data)
