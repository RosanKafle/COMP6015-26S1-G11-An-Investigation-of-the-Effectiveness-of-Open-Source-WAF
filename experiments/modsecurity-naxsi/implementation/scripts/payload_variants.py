"""Controlled candidate transformations; semantic equivalence requires lab review."""
from dataclasses import replace
import html
import re
from urllib.parse import quote
from test_loader import TestCase

TRANSFORMATIONS = ("case", "whitespace", "urlenc", "doubleenc", "separators", "comments", "encoding")

def outside_sql_literals(payload: str, transform) -> str:
    """Preserve simple quoted literals in this starter corpus."""
    pieces = re.split(r"('(?:''|[^'])*'|\"(?:\"\"|[^\"])*\")", payload)
    return "".join(piece if i % 2 else transform(piece) for i, piece in enumerate(pieces))

def transform_case(case: TestCase, name: str) -> TestCase | None:
    if name not in TRANSFORMATIONS:
        raise ValueError(f"Unsupported transformation: {name}")
    if case.category not in ("sqli", "xss") or case.parent_test_id or case.payload.startswith("PLACEHOLDER"):
        return None
    payload = case.payload
    mode = "form"
    if name == "case":
        if case.category == "sqli":
            payload = outside_sql_literals(payload, lambda s: re.sub(
                r"\b(OR|AND|SELECT|UNION)\b", lambda m: m[0].swapcase(), s, flags=re.I))
        else:
            payload = re.sub(r"(<\/?)([A-Za-z]+)",
                             lambda m: m[1] + m[2].upper(), payload)
    elif name in ("whitespace", "separators", "comments"):
        if case.category != "sqli":
            return None
        replacement = {"whitespace": "\t", "separators": "\n", "comments": "/**/"}[name]
        # Preserve the line-comment suffix; its trailing space is meaningful in MySQL.
        prefix, delimiter, suffix = payload.partition("--")
        payload = outside_sql_literals(prefix, lambda s: s.replace(" ", replacement)) + delimiter + suffix
    elif name == "urlenc":
        payload, mode = quote(payload, safe=""), "preencoded"
    elif name == "doubleenc":
        payload, mode = quote(quote(payload, safe=""), safe=""), "preencoded"
    elif name == "encoding":
        if case.category != "xss":
            return None
        payload = html.escape(payload, quote=True)
    if payload == case.payload:
        return None
    return replace(case, test_id=case.test_id + "_" + name.upper(), variant=name,
                   payload=payload, parent_test_id=case.test_id, transformation=name,
                   wire_encoding=mode, review_status="REQUIRES_REVIEW",
                   description=case.description + " Candidate variation; validate intent and wire representation.")
