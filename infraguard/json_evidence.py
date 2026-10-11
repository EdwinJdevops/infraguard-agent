"""Strict, bounded JSON decoding for confidential analysis artifacts."""

from __future__ import annotations

import json
import math
from typing import Any


class EvidenceError(ValueError):
    """A bounded error code; never include source, state, or plan values."""


def read_json_object(payload: bytes, *, max_bytes: int) -> dict[str, Any]:
    if not isinstance(payload, bytes) or len(payload) > max_bytes:
        raise EvidenceError("artifact_size_or_type_invalid")

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in pairs:
            if key in result:
                raise EvidenceError("duplicate_json_key")
            result[key] = value
        return result

    def nonfinite(_: str) -> None:
        raise EvidenceError("nonfinite_json_number")

    def finite(value: str) -> float:
        number = float(value)
        if not math.isfinite(number):
            raise EvidenceError("nonfinite_json_number")
        return number

    try:
        parsed = json.loads(
            payload, object_pairs_hook=unique, parse_constant=nonfinite, parse_float=finite
        )
    except EvidenceError:
        raise
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise EvidenceError("invalid_json") from exc
    if not isinstance(parsed, dict):
        raise EvidenceError("json_object_required")
    stack = [(parsed, 0)]
    while stack:
        value, depth = stack.pop()
        if depth > 64:
            raise EvidenceError("json_nesting_too_deep")
        if isinstance(value, dict):
            stack.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, list):
            stack.extend((v, depth + 1) for v in value)
    return parsed
