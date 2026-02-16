"""
RFC 8785 — JSON Canonicalization Scheme (JCS).

Produces a deterministic, byte-identical JSON representation so that
signing/hashing a JSON object is unambiguous regardless of serializer.

Key rules (RFC 8785 §3):
  1. Sort object keys lexicographically by Unicode code point.
  2. No insignificant whitespace.
  3. Numbers serialized per ES2015 Number.toString().
  4. Strings serialized per ES2015 JSON.stringify() (no optional escapes).
  5. Applied recursively to nested structures.
"""

from __future__ import annotations

import math
from enum import Enum
from typing import Any


def _serialize_string(s: str) -> str:
    """Serialize a string per JCS / ES2015 rules.

    Mandatory escapes: \\, ", and control chars U+0000..U+001F.
    """
    buf: list[str] = ['"']
    for ch in s:
        cp = ord(ch)
        if ch == '\\':
            buf.append('\\\\')
        elif ch == '"':
            buf.append('\\"')
        elif ch == '\b':
            buf.append('\\b')
        elif ch == '\f':
            buf.append('\\f')
        elif ch == '\n':
            buf.append('\\n')
        elif ch == '\r':
            buf.append('\\r')
        elif ch == '\t':
            buf.append('\\t')
        elif cp < 0x20:
            buf.append(f'\\u{cp:04x}')
        else:
            buf.append(ch)
    buf.append('"')
    return ''.join(buf)


def _serialize_number(n: int | float) -> str:
    """Serialize a number per JCS / ES2015 Number.toString().

    - Integers (or floats with no fractional part within safe range) → no decimal.
    - Otherwise → shortest representation that round-trips.
    """
    if isinstance(n, bool):
        # bool is subclass of int in Python — treat as bool not number
        raise TypeError("bool is not a JSON number")

    if isinstance(n, int):
        return str(n)

    # float
    if math.isnan(n) or math.isinf(n):
        raise ValueError("NaN/Infinity not allowed in JCS")

    # If it's an integer value, emit without decimal
    if n == int(n) and abs(n) < 2**53:
        return str(int(n))

    # Shortest round-tripping representation
    r = repr(n)
    # Python repr uses 'e' notation sometimes — JCS wants lowercase 'e'
    # and no leading zeros in exponent, with explicit '+' sign.
    # Actually ES2015: exponent uses 'e+' or 'e-', no leading zeros.
    # Python's repr already does this correctly for most cases.
    # Ensure lowercase
    r = r.lower()
    # Remove trailing zeros after decimal if no exponent
    if 'e' not in r and '.' in r:
        r = r.rstrip('0').rstrip('.')
        if r == '' or r == '-':
            r = '0'
    return r


def canonicalize(obj: Any) -> bytes:
    """Return the JCS (RFC 8785) canonical bytes of a JSON-compatible object."""
    return _serialize(obj).encode('utf-8')


def canonicalize_json(obj: Any) -> str:
    """Return the JCS canonical string."""
    return _serialize(obj)


def _serialize(obj: Any) -> str:
    if obj is None:
        return 'null'
    if isinstance(obj, bool):
        return 'true' if obj else 'false'
    if isinstance(obj, int) and not isinstance(obj, bool):
        return _serialize_number(obj)
    if isinstance(obj, float):
        return _serialize_number(obj)
    if isinstance(obj, str):
        return _serialize_string(obj)
    if isinstance(obj, (list, tuple)):
        inner = ','.join(_serialize(item) for item in obj)
        return f'[{inner}]'
    if isinstance(obj, dict):
        # RFC 8785 §3.2.3: sort by Unicode code point of key string
        sorted_keys = sorted(obj.keys())
        pairs = []
        for k in sorted_keys:
            pairs.append(f'{_serialize_string(k)}:{_serialize(obj[k])}')
        return '{' + ','.join(pairs) + '}'
    # Pydantic models — convert to dict first
    if hasattr(obj, 'model_dump'):
        return _serialize(obj.model_dump(mode='python'))
    # Enum — use the value
    if isinstance(obj, Enum):
        return _serialize(obj.value)
    raise TypeError(f"Cannot JCS-serialize type {type(obj)}")
