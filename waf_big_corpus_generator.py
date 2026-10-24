#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
waf_big_corpus_generator.py  --  COMP6016 S2 2026, Group 11

KALI-side, NETWORK-FREE generator for a large *matched* WAF test corpus.

What it does
------------
Builds one canonical corpus of malicious + benign HTTP test cases spanning
four attack categories (SQLi, XSS, command injection, path traversal) and a
family of payload transformations applied to EVERY category (not just SQLi
and XSS). It then writes a SHA-256 digest over the canonical corpus so that
the same corpus can be proven identical when replayed against ModSecurity,
Coraza and NAXSI.

What it does NOT do
-------------------
- It sends nothing over the network. No WAF, no DVWA, no sockets. It only
  writes files under --out.
- It does not decide pass/block. That is the runner's job (next deliverable),
  which asserts this digest before sending and reuses your existing
  legacy_v10.login() / set_security_low() authenticated-session gate.
- It does not claim every variant is independently exploitable. It records a
  two-tier plan: every case is measured as pass-through; a seeded subset
  (plus all effect-validatable baselines) is flagged for effect validation.

Design notes
------------
- Deterministic: same --seed -> identical corpus -> identical digest. Verify
  by running twice and diffing corpus_digest.txt.
- Transform applicability is explicit per category. Where a transform is not
  meaningful for a category it is simply not generated (no nonsense payloads,
  no padded coverage claims).
- Base payload lists and transform flavor tables are plain data near the top
  of this file. Edit them to raise/lower N or to match your own R11/R12
  payloads exactly. The script prints achieved counts so N is never guessed.
- REVIEW THE BASE PAYLOADS before running in the lab. They target DVWA
  low-security injection points; adjust the INJECTION_POINTS map if your DVWA
  routes differ.

Usage
-----
    python3 waf_big_corpus_generator.py --out corpus_big_YYYYMMDD --seed 6016
    # then, in the runner: assert sha256(corpus.jsonl canonical) == digest
"""

import argparse
import hashlib
import json
import math
import os
import random
import sys
from datetime import datetime, timezone
from urllib.parse import quote

# --------------------------------------------------------------------------
# DVWA low-security injection points (EDIT if your routes differ)
# --------------------------------------------------------------------------
INJECTION_POINTS = {
    "sqli": {"path": "/vulnerabilities/sqli/",   "method": "GET",  "param": "id"},
    "xss":  {"path": "/vulnerabilities/xss_r/",  "method": "GET",  "param": "name"},
    "cmdi": {"path": "/vulnerabilities/exec/",   "method": "POST", "param": "ip"},
    "path": {"path": "/vulnerabilities/fi/",     "method": "GET",  "param": "page"},
}

# How effect is confirmed per category (recorded, used by the runner later):
#   body_substring : look for the canary / marker in the decoded response body
#   body_regex     : look for a regex (path traversal /etc/passwd signature)
#   browser        : requires headless browser to observe real alert() firing
EFFECT_METHOD = {
    "sqli": "body_substring",   # UNION-based cases surface the canary
    "xss":  "browser",          # reflected XSS confirmed by live alert()
    "cmdi": "body_substring",   # echo/printf canary appears in <pre> output
    "path": "body_regex",       # root:.*:0:0: signature from /etc/passwd
}

PATH_EFFECT_REGEX = r"root:.*:0:0:"

# --------------------------------------------------------------------------
# Base payloads.  {CANARY} is substituted with a per-case unique token.
# effect_validatable=True means the intended effect can be confirmed by
# EFFECT_METHOD above; only validatable cases are eligible for the effect
# sample (you cannot "confirm" a blind/time-based case from a body string).
# --------------------------------------------------------------------------
BASE_PAYLOADS = {
    "sqli": [
        # UNION-based: canary is surfaced in the output -> validatable
        {"id": "sqli-union-2col",  "raw": "1' UNION SELECT '{CANARY}','x'-- -",          "validatable": True},
        {"id": "sqli-union-rev",   "raw": "1' UNION SELECT 'x','{CANARY}'-- -",          "validatable": True},
        {"id": "sqli-union-concat","raw": "1' UNION SELECT concat('{CANARY}'),'y'-- -",  "validatable": True},
        {"id": "sqli-union-user",  "raw": "1' UNION SELECT user(),'{CANARY}'-- -",       "validatable": True},
        {"id": "sqli-union-hash",  "raw": "-1' UNION SELECT '{CANARY}',version()-- -",   "validatable": True},
        # Boolean / tautology: effect not confirmable by a canary -> not validatable
        {"id": "sqli-or-1eq1",     "raw": "1' OR '1'='1",                                "validatable": False},
        {"id": "sqli-or-true",     "raw": "' OR 1=1-- -",                                "validatable": False},
        {"id": "sqli-admin",       "raw": "admin'-- -",                                  "validatable": False},
        {"id": "sqli-or-like",     "raw": "1' OR '1' LIKE '1",                           "validatable": False},
        # Error-based
        {"id": "sqli-extractvalue","raw": "1' AND extractvalue(1,concat(0x7e,'{CANARY}'))-- -", "validatable": False},
        {"id": "sqli-updatexml",   "raw": "1' AND updatexml(1,concat(0x7e,'{CANARY}'),1)-- -",  "validatable": False},
        # Stacked / time-based (blind) -> not body-confirmable
        {"id": "sqli-sleep",       "raw": "1' AND SLEEP(3)-- -",                         "validatable": False},
        {"id": "sqli-stacked",     "raw": "1'; SELECT SLEEP(3)-- -",                     "validatable": False},
        {"id": "sqli-benchmark",   "raw": "1' AND BENCHMARK(1000000,MD5('{CANARY}'))-- -", "validatable": False},
    ],
    "xss": [
        {"id": "xss-script",       "raw": "<script>alert('{CANARY}')</script>",          "validatable": True},
        {"id": "xss-script-dq",    "raw": "<script>alert(\"{CANARY}\")</script>",        "validatable": True},
        {"id": "xss-img-onerror",  "raw": "<img src=x onerror=alert('{CANARY}')>",       "validatable": True},
        {"id": "xss-svg-onload",   "raw": "<svg onload=alert('{CANARY}')>",              "validatable": True},
        {"id": "xss-body-onload",  "raw": "<body onload=alert('{CANARY}')>",             "validatable": True},
        {"id": "xss-iframe-js",    "raw": "<iframe src=javascript:alert('{CANARY}')>",   "validatable": True},
        {"id": "xss-input-focus",  "raw": "<input autofocus onfocus=alert('{CANARY}')>", "validatable": True},
        {"id": "xss-details",      "raw": "<details open ontoggle=alert('{CANARY}')>",   "validatable": True},
        {"id": "xss-a-href",       "raw": "<a href=javascript:alert('{CANARY}')>x</a>",  "validatable": True},
        {"id": "xss-marquee",      "raw": "<marquee onstart=alert('{CANARY}')>",         "validatable": True},
        {"id": "xss-video",        "raw": "<video><source onerror=alert('{CANARY}')>",   "validatable": True},
        {"id": "xss-img-src-js",   "raw": "<img src=1 onerror=alert(`{CANARY}`)>",       "validatable": True},
        {"id": "xss-close-script", "raw": "</script><script>alert('{CANARY}')</script>", "validatable": True},
        {"id": "xss-textarea",     "raw": "</textarea><script>alert('{CANARY}')</script>","validatable": True},
    ],
    "cmdi": [
        # The leading "127.0.0.1 <SEP> <cmd>" structure; <SEP> is a transform axis.
        {"id": "cmdi-echo",        "raw": "127.0.0.1 ; echo {CANARY}",                   "validatable": True},
        {"id": "cmdi-printf",      "raw": "127.0.0.1 ; printf {CANARY}",                 "validatable": True},
        {"id": "cmdi-echo-sub",    "raw": "127.0.0.1 ; echo $(echo {CANARY})",          "validatable": True},
        {"id": "cmdi-id",          "raw": "127.0.0.1 ; echo {CANARY}; id",              "validatable": True},
        {"id": "cmdi-uname",       "raw": "127.0.0.1 ; echo {CANARY}; uname -a",        "validatable": True},
        {"id": "cmdi-whoami",      "raw": "127.0.0.1 ; whoami; echo {CANARY}",          "validatable": True},
        {"id": "cmdi-cat-passwd",  "raw": "127.0.0.1 ; echo {CANARY}; cat /etc/passwd", "validatable": True},
        {"id": "cmdi-backtick",    "raw": "127.0.0.1 ; echo `echo {CANARY}`",           "validatable": True},
        {"id": "cmdi-env",         "raw": "127.0.0.1 ; echo {CANARY}; env",             "validatable": True},
        {"id": "cmdi-ls",          "raw": "127.0.0.1 ; echo {CANARY}; ls -la",          "validatable": True},
    ],
    "path": [
        {"id": "path-etc-passwd",  "raw": "../../../../etc/passwd",                      "validatable": True},
        {"id": "path-deep-passwd", "raw": "../../../../../../etc/passwd",                "validatable": True},
        {"id": "path-dotdot-abs",  "raw": "/../../../../etc/passwd",                     "validatable": True},
        {"id": "path-trailing",    "raw": "../../../../etc/passwd%00",                   "validatable": True},
        {"id": "path-php-filter",  "raw": "php://filter/convert.base64-encode/resource=/etc/passwd", "validatable": False},
        {"id": "path-php-input",   "raw": "php://input",                                 "validatable": False},
        {"id": "path-data-wrap",   "raw": "data://text/plain;base64,aGVsbG8=",          "validatable": False},
        {"id": "path-expect",      "raw": "expect://id",                                 "validatable": False},
        {"id": "path-shallow",     "raw": "../../etc/passwd",                            "validatable": True},
        {"id": "path-mixed-slash", "raw": "..\\../..\\../etc/passwd",                    "validatable": True},
    ],
}

# --------------------------------------------------------------------------
# Transform families.  Each entry: applicable categories + a builder that
# takes a raw payload and returns a list of (flavor, wire_payload).
# "baseline" is handled separately (identity, always generated, always
# effect-validated when the base is validatable).
# --------------------------------------------------------------------------

def _url_encode_full(p):
    return quote(p, safe="")

def _url_encode_min(p):
    # encode only characters a careless app/dev would encode: space + a few
    return p.replace(" ", "%20").replace("<", "%3C").replace(">", "%3E").replace("'", "%27")

def _double_url_full(p):
    return quote(quote(p, safe=""), safe="")

def _double_url_percent(p):
    # single-encode, then double-encode only the percent signs (mixed depth)
    once = quote(p, safe="")
    return once.replace("%", "%25")

def t_url_encode(p):
    return [("url_full", _url_encode_full(p)),
            ("url_min",  _url_encode_min(p))]

def t_double_url(p):
    return [("dblurl_full",    _double_url_full(p)),
            ("dblurl_percent", _double_url_percent(p))]

def t_whitespace(p):
    if " " not in p:
        return []
    return [("ws_tab",     p.replace(" ", "\t")),
            ("ws_pct09",   p.replace(" ", "%09")),
            ("ws_pct0b",   p.replace(" ", "%0b")),
            ("ws_comment", p.replace(" ", "/**/")),
            ("ws_pct0a",   p.replace(" ", "%0a"))]

def t_case_mod(p):
    rng = random.Random(hashlib.sha1(("case"+p).encode()).hexdigest())
    def alt(s):
        out = []
        for i, ch in enumerate(s):
            out.append(ch.upper() if (i % 2 == 0) else ch.lower())
        return "".join(out)
    def rand(s):
        return "".join(ch.upper() if (ch.isalpha() and rng.random() > 0.5) else ch for ch in s)
    return [("case_alt",  alt(p)),
            ("case_rand", rand(p)),
            ("case_upper_kw", p.upper())]

def t_comments(p):
    # SQL comment-based obfuscation; assumes a space-separated SQL payload
    out = []
    if " " in p:
        out.append(("cmt_inline", p.replace(" ", "/**/")))
    out.append(("cmt_versioned", p.replace("UNION", "/*!50000UNION*/").replace("SELECT", "/*!50000SELECT*/")))
    out.append(("cmt_hash_tail", p.replace("-- -", "#")))
    return out

def t_html_entity(p):
    dec = p.replace("<", "&#60;").replace(">", "&#62;").replace("'", "&#39;").replace("\"", "&#34;")
    hexe = p.replace("<", "&#x3c;").replace(">", "&#x3e;").replace("'", "&#x27;").replace("\"", "&#x22;")
    named = p.replace("<", "&lt;").replace(">", "&gt;").replace("'", "&apos;").replace("\"", "&quot;")
    return [("ent_dec", dec), ("ent_hex", hexe), ("ent_named", named)]

def t_separators(p):
    # command-injection separator axis -- the finding that matters.
    # replace the canonical " ; " separator with alternatives.
    if " ; " not in p:
        return []
    out = []
    out.append(("sep_semi",    p))                                   # identity (;)
    out.append(("sep_newline", p.replace(" ; ", " \n ")))
    out.append(("sep_pct0a",   p.replace(" ; ", " %0a ")))
    out.append(("sep_and",     p.replace(" ; ", " && ")))
    out.append(("sep_pipe",    p.replace(" ; ", " | ")))
    out.append(("sep_nl_and",  p.replace(" ; ", " \n&& ")))
    return out

TRANSFORMS = {
    "url_encode":       {"cats": {"sqli", "xss", "cmdi", "path"}, "fn": t_url_encode},
    "double_url_encode":{"cats": {"sqli", "xss", "cmdi", "path"}, "fn": t_double_url},
    "whitespace":       {"cats": {"sqli", "xss", "cmdi"},         "fn": t_whitespace},
    "case_mod":         {"cats": {"sqli", "xss"},                 "fn": t_case_mod},
    "comments":         {"cats": {"sqli"},                        "fn": t_comments},
    "html_entity":      {"cats": {"xss"},                         "fn": t_html_entity},
    "separators":       {"cats": {"cmdi"},                        "fn": t_separators},
}

# --------------------------------------------------------------------------
# Benign corpus -- a real population, including metacharacter-bearing natural
# text (the NAXSI false-positive probe), per category param.
# --------------------------------------------------------------------------
BENIGN_TEMPLATES = {
    "sqli": [  # id param: numbers and ordinary record-ish text
        "1", "2", "3", "42", "1001",
        "O'Brien", "D'Angelo", "user-123", "order #4471",
        "Review: 5/5 would recommend", "size M/L", "a and b",
    ],
    "xss": [  # name param: ordinary names and text with special chars
        "Jean-Luc", "O'Brien", "Anne Marie", "José", "Zoë",
        "<3 the service", "price > cost", "a < b inequality",
        "email me at a@b.com", "C# and C++ notes", "math: 1 < 2 && 2 < 3",
    ],
    "cmdi": [  # ip param: real hosts + natural text with shell metacharacters
        "127.0.0.1", "8.8.8.8", "192.168.1.1", "google.com", "localhost",
        "Chain steps with a semicolon; then pipe output | to a log",
        "Use && between commands in the runbook",
        "Backups run nightly & rotate weekly",
        "Ping the gateway, then check DNS",
        "Report latency > 100ms to the channel",
    ],
    "path": [  # page param: legitimate includes + benign relative paths
        "include.php", "index.php", "home", "about.php", "help",
        "Store nightly backups under ../archive/2026 per our folder convention",
        "docs/readme.txt", "reports/2026-Q3.html",
        "See ./notes for the folder layout",
        "path uses forward slashes like a/b/c",
    ],
}
# extra benign filler to lift the population to a statistically useful size
BENIGN_FILLERS = [
    "status ok", "all systems nominal", "weekly summary",
    "please review", "thanks team", "see attached",
    "follow up tomorrow", "approved by lead", "pending sign-off",
    "no action needed",
]


def canary_for(test_id):
    h = hashlib.sha1(test_id.encode()).hexdigest()[:8].upper()
    return "C" + h  # alnum, survives case/entity/url transforms intact


def build_corpus(seed, sample_rate):
    rng = random.Random(seed)
    records = []

    # ---- malicious: baseline + variants ----
    for cat, bases in BASE_PAYLOADS.items():
        ip = INJECTION_POINTS[cat]
        for b in bases:
            # BASELINE (identity)
            base_tid = f"BIG-{cat.upper()}-{b['id']}-baseline"
            can = canary_for(base_tid)
            raw = b["raw"].replace("{CANARY}", can)
            records.append({
                "test_id": base_tid, "category": cat, "base_id": b["id"],
                "transform": "baseline", "flavor": "identity", "tier": "baseline",
                "benign": False, "method": ip["method"], "path": ip["path"],
                "param": ip["param"], "raw_payload": raw, "wire_payload": raw,
                "canary": can if "{CANARY}" in b["raw"] else None,
                "effect_validatable": bool(b["validatable"]),
                "effect_method": EFFECT_METHOD[cat],
                "effect_marker": (can if ("{CANARY}" in b["raw"] and b["validatable"])
                                  else (PATH_EFFECT_REGEX if cat == "path" and b["validatable"] else None)),
                # every validatable baseline is always effect-sampled:
                "effect_sample": bool(b["validatable"]),
            })
            # VARIANTS
            for tname, tdef in TRANSFORMS.items():
                if cat not in tdef["cats"]:
                    continue
                # transform operates on the raw (canary already substituted)
                for flavor, wire in tdef["fn"](raw):
                    tid = f"BIG-{cat.upper()}-{b['id']}-{tname}-{flavor}"
                    records.append({
                        "test_id": tid, "category": cat, "base_id": b["id"],
                        "transform": tname, "flavor": flavor, "tier": "variant",
                        "benign": False, "method": ip["method"], "path": ip["path"],
                        "param": ip["param"], "raw_payload": raw, "wire_payload": wire,
                        "canary": can if "{CANARY}" in b["raw"] else None,
                        "effect_validatable": bool(b["validatable"]),
                        "effect_method": EFFECT_METHOD[cat],
                        "effect_marker": (can if ("{CANARY}" in b["raw"] and b["validatable"])
                                          else (PATH_EFFECT_REGEX if cat == "path" and b["validatable"] else None)),
                        "effect_sample": False,  # filled by stratified sampler below
                    })

    # ---- stratified effect-validation sample over validatable VARIANTS ----
    strata = {}
    for r in records:
        if r["tier"] == "variant" and r["effect_validatable"]:
            strata.setdefault((r["category"], r["transform"]), []).append(r)
    for key, group in sorted(strata.items()):
        group_sorted = sorted(group, key=lambda r: r["test_id"])
        k = max(1, math.ceil(sample_rate * len(group_sorted)))
        for r in rng.sample(group_sorted, k):
            r["effect_sample"] = True

    # ---- benign population ----
    for cat, texts in BENIGN_TEMPLATES.items():
        ip = INJECTION_POINTS[cat]
        pool = list(texts)
        # expand with fillers to lift N, seeded & reproducible
        for t in texts:
            for f in BENIGN_FILLERS:
                pool.append(f"{t} - {f}")
        pool = sorted(set(pool))
        for i, text in enumerate(pool):
            tid = f"BIG-BENIGN-{cat.upper()}-{i:04d}"
            records.append({
                "test_id": tid, "category": "benign", "base_id": f"benign-{cat}",
                "transform": "none", "flavor": "natural", "tier": "benign",
                "benign": True, "method": ip["method"], "path": ip["path"],
                "param": ip["param"], "raw_payload": text, "wire_payload": text,
                "canary": None, "effect_validatable": False,
                "effect_method": "none", "effect_marker": None,
                "effect_sample": False, "benign_probe_category": cat,
            })

    records.sort(key=lambda r: r["test_id"])
    return records


def canonical_digest(records):
    lines = []
    for r in records:
        # exclude nothing volatile (no timestamps in records); stable ordering
        lines.append(json.dumps(r, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    blob = "\n".join(lines).encode("utf-8")
    return hashlib.sha256(blob).hexdigest(), lines


def summarise(records):
    by_cat = {}
    by_cat_tf = {}
    tiers = {"baseline": 0, "variant": 0, "benign": 0}
    eff_sample = 0
    for r in records:
        by_cat[r["category"]] = by_cat.get(r["category"], 0) + 1
        tiers[r["tier"]] = tiers.get(r["tier"], 0) + 1
        if r["tier"] in ("baseline", "variant"):
            key = f'{r["category"]}/{r["transform"]}'
            by_cat_tf[key] = by_cat_tf.get(key, 0) + 1
        if r.get("effect_sample"):
            eff_sample += 1
    malicious = tiers["baseline"] + tiers["variant"]
    return {
        "total_cases": len(records),
        "malicious_cases": malicious,
        "benign_cases": tiers["benign"],
        "baseline_cases": tiers["baseline"],
        "variant_cases": tiers["variant"],
        "effect_sampled_cases": eff_sample,
        "by_category": dict(sorted(by_cat.items())),
        "by_category_transform": dict(sorted(by_cat_tf.items())),
    }


def main():
    ap = argparse.ArgumentParser(description="Generate a matched WAF test corpus (network-free).")
    ap.add_argument("--out", required=True, help="output directory (must not already contain a corpus)")
    ap.add_argument("--seed", type=int, default=6016, help="RNG seed (determinism)")
    ap.add_argument("--sample-rate", type=float, default=0.15,
                    help="fraction of validatable variants flagged for effect validation (per stratum)")
    ap.add_argument("--reps", type=int, default=3, help="repetitions per case recorded in metadata (runner sends these)")
    args = ap.parse_args()

    out = args.out
    corpus_path = os.path.join(out, "corpus.jsonl")
    if os.path.isdir(out) and os.path.exists(corpus_path) and os.path.getsize(corpus_path) > 0:
        print(f"REFUSING: {corpus_path} already exists and is non-empty.", file=sys.stderr)
        sys.exit(2)
    os.makedirs(out, exist_ok=True)

    records = build_corpus(args.seed, args.sample_rate)
    digest, lines = canonical_digest(records)
    summary = summarise(records)

    with open(corpus_path, "w", encoding="utf-8") as fh:
        for ln in lines:
            fh.write(ln + "\n")
    with open(os.path.join(out, "corpus_digest.txt"), "w", encoding="utf-8") as fh:
        fh.write(digest + "\n")
    with open(os.path.join(out, "corpus_summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, sort_keys=True)
    with open(os.path.join(out, "run_metadata.json"), "w", encoding="utf-8") as fh:
        json.dump({
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "seed": args.seed, "sample_rate": args.sample_rate, "reps": args.reps,
            "corpus_sha256": digest,
            "note": "Digest covers corpus.jsonl canonical form only; this metadata file is not part of the digest.",
        }, fh, indent=2, sort_keys=True)

    print(f"corpus.jsonl        : {summary['total_cases']} cases")
    print(f"  malicious         : {summary['malicious_cases']} "
          f"(baseline {summary['baseline_cases']}, variant {summary['variant_cases']})")
    print(f"  benign            : {summary['benign_cases']}")
    print(f"  effect-sampled    : {summary['effect_sampled_cases']} "
          f"(all validatable baselines + {int(args.sample_rate*100)}% of validatable variants)")
    print(f"corpus_sha256       : {digest}")
    print(f"observations @reps{args.reps} x 3 WAFs : {summary['total_cases'] * args.reps * 3}")
    print("\nby category:")
    for k, v in summary["by_category"].items():
        print(f"  {k:8s} {v}")
    print("\nby category/transform:")
    for k, v in summary["by_category_transform"].items():
        print(f"  {k:28s} {v}")


if __name__ == "__main__":
    main()
