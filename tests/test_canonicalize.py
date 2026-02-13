"""Tests for RFC 8785 JCS canonicalization."""

import json
import pytest
from core.canonicalize import canonicalize, canonicalize_json


class TestJCSCanonical:
    """Test JCS canonicalization per RFC 8785."""

    def test_empty_object(self):
        assert canonicalize({}) == b'{}'

    def test_empty_array(self):
        assert canonicalize([]) == b'[]'

    def test_null(self):
        assert canonicalize(None) == b'null'

    def test_boolean_true(self):
        assert canonicalize(True) == b'true'

    def test_boolean_false(self):
        assert canonicalize(False) == b'false'

    def test_integer(self):
        assert canonicalize(42) == b'42'
        assert canonicalize(0) == b'0'
        assert canonicalize(-1) == b'-1'

    def test_string(self):
        assert canonicalize("hello") == b'"hello"'

    def test_string_escapes(self):
        assert canonicalize("a\"b") == b'"a\\"b"'
        assert canonicalize("a\\b") == b'"a\\\\b"'
        assert canonicalize("a\nb") == b'"a\\nb"'
        assert canonicalize("a\tb") == b'"a\\tb"'

    def test_key_sorting(self):
        """RFC 8785 §3.2.3: keys sorted by Unicode code point."""
        obj = {"b": 2, "a": 1, "c": 3}
        result = canonicalize_json(obj)
        assert result == '{"a":1,"b":2,"c":3}'

    def test_key_sorting_numbers_vs_letters(self):
        obj = {"z": 1, "1": 2, "a": 3}
        result = canonicalize_json(obj)
        # '1' (U+0031) < 'a' (U+0061) < 'z' (U+007A)
        assert result == '{"1":2,"a":3,"z":1}'

    def test_nested_object_sorting(self):
        obj = {"b": {"d": 4, "c": 3}, "a": 1}
        result = canonicalize_json(obj)
        assert result == '{"a":1,"b":{"c":3,"d":4}}'

    def test_no_whitespace(self):
        """JCS must not include insignificant whitespace."""
        obj = {"key": "value", "num": 42}
        result = canonicalize_json(obj)
        assert ' ' not in result.replace('"value"', '').replace('"key"', '').replace('"num"', '')

    def test_deterministic(self):
        """Same object → identical bytes every time."""
        obj = {"z": [1, 2, 3], "a": {"c": True, "b": None}}
        r1 = canonicalize(obj)
        r2 = canonicalize(obj)
        assert r1 == r2

    def test_equivalent_json_different_order(self):
        """Different key orders produce identical canonical output."""
        obj1 = {"name": "Alice", "age": 30, "active": True}
        obj2 = {"active": True, "name": "Alice", "age": 30}
        obj3 = {"age": 30, "active": True, "name": "Alice"}
        assert canonicalize(obj1) == canonicalize(obj2) == canonicalize(obj3)

    def test_array_order_preserved(self):
        """Array element order must be preserved."""
        result = canonicalize_json([3, 1, 2])
        assert result == '[3,1,2]'

    def test_float_integer_value(self):
        """Float with no fractional part serialized as integer."""
        assert canonicalize(1.0) == b'1'

    def test_complex_nested(self):
        obj = {
            "claims": [
                {"id": "c1", "text": "hello"},
                {"id": "c2", "text": "world"},
            ],
            "answer": "hello world",
        }
        result = canonicalize(obj)
        # Must be valid JSON
        parsed = json.loads(result)
        assert parsed["answer"] == "hello world"
        assert len(parsed["claims"]) == 2
