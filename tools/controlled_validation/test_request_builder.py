"""Offline tests for exact prepared-request behaviour."""

import unittest
from urllib.parse import unquote, unquote_plus

from tools.controlled_validation.request_builder import (
    prepare_catalogue_request,
)


BASE_URL = "http://waf-lab.local/DVWA"


def row(**overrides):
    values = {
        "test_id": "TEST-001",
        "base_test_id": "TEST-001",
        "variant_id": "original",
        "method": "GET",
        "endpoint": "/vulnerabilities/sqli/",
        "input_location": "query",
        "parameter_name": "id",
        "fixed_parameters": "Submit=Submit",
        "raw_payload": "' OR '1'='1' -- -",
        "transform": "none",
        "encoding_layers": "0",
    }
    values.update(overrides)
    return values


class RequestBuilderTests(unittest.TestCase):
    def test_raw_query_payload(self):
        result = prepare_catalogue_request(BASE_URL, row())

        self.assertEqual(
            result.wire_payload,
            "'%20OR%20'1'='1'%20--%20-",
        )
        self.assertEqual(
            unquote(result.wire_payload),
            "' OR '1'='1' -- -",
        )

    def test_single_encoded_query(self):
        result = prepare_catalogue_request(
            BASE_URL,
            row(
                test_id="TEST-U1",
                variant_id="url_encode_1",
                transform="url_encode",
                encoding_layers="1",
            ),
        )

        self.assertEqual(
            result.wire_payload,
            "%27%20OR%20%271%27%3D%271%27%20--%20-",
        )
        self.assertEqual(
            unquote(result.wire_payload),
            "' OR '1'='1' -- -",
        )

    def test_double_encoded_query(self):
        result = prepare_catalogue_request(
            BASE_URL,
            row(
                test_id="TEST-U2",
                variant_id="url_encode_2",
                transform="url_encode",
                encoding_layers="2",
            ),
        )

        self.assertIn("%2527", result.wire_payload)
        self.assertNotIn("%252527", result.wire_payload)
        self.assertEqual(
            unquote(unquote(result.wire_payload)),
            "' OR '1'='1' -- -",
        )

    def test_entity_ampersands_do_not_create_parameters(self):
        result = prepare_catalogue_request(
            BASE_URL,
            row(
                test_id="TEST-ENTITY",
                endpoint="/vulnerabilities/xss_r/",
                parameter_name="name",
                raw_payload="&lt;script&gt;alert(1)&lt;/script&gt;",
            ),
        )

        query = result.prepared.path_url.split("?", 1)[1]

        self.assertEqual(query.count("&"), 1)
        self.assertIn("%26lt%3B", result.wire_payload)
        self.assertEqual(
            unquote(result.wire_payload),
            "&lt;script&gt;alert(1)&lt;/script&gt;",
        )

    def test_form_payload_preserves_command(self):
        result = prepare_catalogue_request(
            BASE_URL,
            row(
                test_id="TEST-FORM",
                method="POST",
                endpoint="/vulnerabilities/exec/",
                input_location="form",
                parameter_name="ip",
                raw_payload="127.0.0.1 && id",
            ),
        )

        self.assertEqual(
            result.wire_payload,
            "127.0.0.1+%26%26+id",
        )
        self.assertEqual(
            unquote_plus(result.wire_payload),
            "127.0.0.1 && id",
        )
        self.assertIn("Submit=Submit", str(result.prepared.body))

    def test_correlation_headers_present(self):
        result = prepare_catalogue_request(BASE_URL, row())

        self.assertEqual(
            result.prepared.headers["X-WAF-Test-ID"],
            "TEST-001",
        )
        self.assertEqual(
            result.prepared.headers["X-WAF-Base-Test-ID"],
            "TEST-001",
        )
        self.assertEqual(
            result.prepared.headers["X-WAF-Variant-ID"],
            "original",
        )

    def test_unsupported_location_rejected(self):
        with self.assertRaises(NotImplementedError):
            prepare_catalogue_request(
                BASE_URL,
                row(input_location="xml"),
            )


if __name__ == "__main__":
    unittest.main()
