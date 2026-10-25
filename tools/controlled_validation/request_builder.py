"""Prepare controlled requests without unintended payload re-encoding."""

from dataclasses import dataclass
from typing import Mapping
from urllib.parse import parse_qsl, quote, quote_plus, urlencode

from requests import PreparedRequest, Request

from tools.controlled_validation.encoding import apply_transform


@dataclass(frozen=True)
class PreparedEnvelope:
    """Prepared HTTP request plus payload evidence."""

    prepared: PreparedRequest
    transformed_payload: str
    wire_payload: str


def _fixed_parameters(value: str):
    if not value:
        return []

    return parse_qsl(value, keep_blank_values=True)


def _normal_query_value(value: str) -> str:
    """Encode delimiters while retaining useful raw representation."""
    return quote(
        value,
        safe="'()*/,-=<>:$",
    )


def _extract_parameter(serialized: str, parameter_name: str) -> str:
    encoded_name = quote_plus(parameter_name)
    prefix = f"{encoded_name}="

    for component in serialized.split("&"):
        if component.startswith(prefix):
            return component[len(prefix):]

    raise ValueError(
        f"Parameter {parameter_name!r} missing from serialized request"
    )


def prepare_catalogue_request(
    base_url: str,
    row: Mapping[str, str],
) -> PreparedEnvelope:
    """Build a request while preserving declared encoding layers."""
    method = row["method"].upper()
    endpoint = row["endpoint"]
    input_location = row["input_location"]
    parameter_name = row["parameter_name"]
    raw_payload = row["raw_payload"]
    transform = row["transform"]
    encoding_layers = int(row["encoding_layers"])

    transformed = apply_transform(
        raw_payload,
        transform,
        encoding_layers,
    )

    headers = {
        "User-Agent": "COMP6016-Controlled-WAF-Test/1.0",
        "X-WAF-Test-ID": row["test_id"],
        "X-WAF-Base-Test-ID": row["base_test_id"],
        "X-WAF-Variant-ID": row["variant_id"],
    }

    endpoint_url = (
        f"{base_url.rstrip('/')}/"
        f"{endpoint.lstrip('/')}"
    )

    fixed = _fixed_parameters(row.get("fixed_parameters", ""))

    if input_location == "query":
        if transform == "none":
            serialized_payload = _normal_query_value(raw_payload)
        else:
            serialized_payload = transformed

        query_components = [
            f"{quote_plus(parameter_name)}={serialized_payload}"
        ]

        if fixed:
            query_components.append(urlencode(fixed))

        request = Request(
            method=method,
            url=f"{endpoint_url}?{'&'.join(query_components)}",
            headers=headers,
        )

        prepared = request.prepare()
        prepared_query = prepared.path_url.split("?", 1)[1]
        wire_payload = _extract_parameter(
            prepared_query,
            parameter_name,
        )

    elif input_location == "form":
        if transform == "none":
            serialized_payload = quote_plus(raw_payload, safe="")
        else:
            serialized_payload = transformed

        body_components = [
            f"{quote_plus(parameter_name)}={serialized_payload}"
        ]

        if fixed:
            body_components.append(urlencode(fixed))

        body = "&".join(body_components)
        headers["Content-Type"] = "application/x-www-form-urlencoded"

        request = Request(
            method=method,
            url=endpoint_url,
            headers=headers,
            data=body,
        )

        prepared = request.prepare()
        wire_payload = _extract_parameter(
            str(prepared.body),
            parameter_name,
        )

    else:
        raise NotImplementedError(
            f"Input location not implemented: {input_location}"
        )

    return PreparedEnvelope(
        prepared=prepared,
        transformed_payload=transformed,
        wire_payload=wire_payload,
    )
