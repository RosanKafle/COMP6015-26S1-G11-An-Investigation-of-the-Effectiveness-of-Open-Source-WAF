"""Explicit payload transformations for controlled WAF testing."""

from urllib.parse import quote, unquote


SUPPORTED_TRANSFORMS = {
    "none",
    "url_encode",
    "encode_slashes",
}


def percent_encode(value: str, layers: int) -> str:
    """Apply exactly the requested number of percent-encoding layers."""
    if layers not in {1, 2}:
        raise ValueError("URL encoding layers must be 1 or 2")

    result = value
    for _ in range(layers):
        result = quote(result, safe="")

    return result


def encode_slashes(value: str, layers: int) -> str:
    """Encode slash characters without encoding the remaining payload."""
    if layers != 1:
        raise ValueError("encode_slashes requires exactly one layer")

    return value.replace("/", "%2F")


def apply_transform(
    raw_payload: str,
    transform: str,
    encoding_layers: int,
) -> str:
    """Return the transformed value to place directly on the wire."""
    if transform not in SUPPORTED_TRANSFORMS:
        raise ValueError(f"Unsupported transform: {transform}")

    if transform == "none":
        if encoding_layers != 0:
            raise ValueError("none transform requires zero encoding layers")
        return raw_payload

    if transform == "url_encode":
        return percent_encode(raw_payload, encoding_layers)

    if transform == "encode_slashes":
        return encode_slashes(raw_payload, encoding_layers)

    raise AssertionError("Unreachable transformation branch")


def decode_layers(value: str, layers: int) -> str:
    """Decode a payload exactly the requested number of times."""
    if layers < 0:
        raise ValueError("Decode layers cannot be negative")

    result = value
    for _ in range(layers):
        result = unquote(result)

    return result
