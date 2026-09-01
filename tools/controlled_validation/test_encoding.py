"""Unit tests for controlled payload transformations."""

import unittest

from tools.controlled_validation.encoding import (
    apply_transform,
    decode_layers,
)


class EncodingTests(unittest.TestCase):
    def test_none_preserves_raw_payload(self):
        raw = "' OR '1'='1' -- -"
        self.assertEqual(apply_transform(raw, "none", 0), raw)

    def test_single_url_encoding(self):
        raw = "' OR '1'='1' -- -"
        expected = "%27%20OR%20%271%27%3D%271%27%20--%20-"

        encoded = apply_transform(raw, "url_encode", 1)

        self.assertEqual(encoded, expected)
        self.assertEqual(decode_layers(encoded, 1), raw)

    def test_double_url_encoding(self):
        raw = "' OR '1'='1' -- -"
        expected = (
            "%2527%2520OR%2520%25271%2527"
            "%253D%25271%2527%2520--%2520-"
        )

        encoded = apply_transform(raw, "url_encode", 2)

        self.assertEqual(encoded, expected)
        self.assertNotIn("%252527", encoded)
        self.assertEqual(decode_layers(encoded, 2), raw)
        self.assertNotEqual(decode_layers(encoded, 1), raw)

    def test_xss_url_encoding(self):
        raw = "<script>alert(1)</script>"
        expected = "%3Cscript%3Ealert%281%29%3C%2Fscript%3E"

        encoded = apply_transform(raw, "url_encode", 1)

        self.assertEqual(encoded, expected)
        self.assertEqual(decode_layers(encoded, 1), raw)

    def test_traversal_double_encoding(self):
        raw = "../../etc/passwd"

        encoded = apply_transform(raw, "url_encode", 2)

        self.assertIn("%252F", encoded)
        self.assertEqual(decode_layers(encoded, 2), raw)

    def test_encode_slashes_only(self):
        raw = "../../etc/passwd"
        expected = "..%2F..%2Fetc%2Fpasswd"

        self.assertEqual(
            apply_transform(raw, "encode_slashes", 1),
            expected,
        )

    def test_invalid_none_layers_rejected(self):
        with self.assertRaises(ValueError):
            apply_transform("payload", "none", 1)

    def test_invalid_url_layer_rejected(self):
        with self.assertRaises(ValueError):
            apply_transform("payload", "url_encode", 3)

    def test_unknown_transform_rejected(self):
        with self.assertRaises(ValueError):
            apply_transform("payload", "unknown", 0)


if __name__ == "__main__":
    unittest.main()
