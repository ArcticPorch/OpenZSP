"""
Shared validation primitives.

These live outside both the evidence and risk packages so that neither has to
depend on the other just to validate a float. Every validator raises TypeError
for a wrong type and ValueError for a well-typed but unacceptable value; the
distinction is part of the contract and is asserted by the tests.
"""

from datetime import datetime
import math
from typing import Any


def validate_numeric(val: Any, name: str, min_val: float, max_val: float) -> float:
    """Validates that a value is a real, finite float or int (not bool) within a range."""
    if isinstance(val, bool):
        # bool is a subclass of int, so this must be checked first. Silently
        # accepting True as 1.0 would let a rule emit a "score" that is really a flag.
        raise TypeError(f"{name} must be a real number, not a boolean")
    if not isinstance(val, (int, float)):
        raise TypeError(f"{name} must be a number (float or int), got {type(val).__name__}")
    if not math.isfinite(val):
        raise ValueError(f"{name} must be a finite number, got {val}")
    val_f = float(val)
    if not (min_val <= val_f <= max_val):
        raise ValueError(f"{name} must be between {min_val} and {max_val}, got {val_f}")
    return val_f


def validate_non_empty_str(val: Any, name: str) -> str:
    """Validates that a value is a non-empty string."""
    if not isinstance(val, str):
        raise TypeError(f"{name} must be a string, got {type(val).__name__}")
    if not val.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return val


def validate_tz_datetime(val: Any, name: str) -> datetime:
    """Validates that a value is a timezone-aware datetime instance."""
    if not isinstance(val, datetime):
        raise TypeError(f"{name} must be a datetime instance, got {type(val).__name__}")
    if val.tzinfo is None or val.tzinfo.utcoffset(val) is None:
        raise ValueError(f"{name} must be a timezone-aware datetime")
    return val


def validate_str_pair_tuple(val: Any, name: str) -> None:
    """Validates a tuple[tuple[str, str], ...] structure with non-empty members."""
    if not isinstance(val, tuple):
        raise TypeError(f"{name} must be a tuple, got {type(val).__name__}")
    for idx, item in enumerate(val):
        if not isinstance(item, tuple) or len(item) != 2:
            raise TypeError(f"{name}[{idx}] must be a tuple of length 2, got {item}")
        key, value = item
        validate_non_empty_str(key, f"{name}[{idx}][0] (key)")
        validate_non_empty_str(value, f"{name}[{idx}][1] (value)")


def validate_keyed_tuple(val: Any, name: str) -> None:
    """Validates a tuple[tuple[str, Any], ...] structure; only the key is constrained."""
    if not isinstance(val, tuple):
        raise TypeError(f"{name} must be a tuple, got {type(val).__name__}")
    for idx, item in enumerate(val):
        if not isinstance(item, tuple) or len(item) != 2:
            raise TypeError(f"{name}[{idx}] must be a tuple of length 2, got {item}")
        validate_non_empty_str(item[0], f"{name}[{idx}][0] (key)")
