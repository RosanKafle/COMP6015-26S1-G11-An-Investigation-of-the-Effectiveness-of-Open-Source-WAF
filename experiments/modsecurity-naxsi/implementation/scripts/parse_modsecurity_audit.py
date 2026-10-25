"""Extract run-specific native ModSecurity transactions; never guess from status."""
import argparse
import csv
import re
from pathlib import Path
from result_reader import read_results, one_condition
from result_writer import sha256

EVENT_FIELDS = ["run_id", "waf", "test_id", "request_id", "transaction_id", "rule_id",
                "rule_group", "intervention", "evidence_reference"]
DECISION_FIELDS = ["run_id", "waf", "test_id", "request_id", "waf_action", "evidence_reference", "notes"]

def transactions(text):
    sections = {}
    token = None
    section = None
    for number, line in enumerate(text.splitlines(), 1):
        boundary = re.fullmatch(r"--([A-Za-z0-9_-]+)-([A-Z])--", line.strip())
        if boundary:
            current, part = boundary.groups()
            if part == "A":
                token, sections = current, {}
            if current != token:
                section = None
                continue
            section = part
            sections.setdefault(part, [])
            if part == "Z":
                yield token, sections
                token, section, sections = None, None, {}
        elif token and section:
            sections[section].append((number, line))

def extract(raw, audit, output):
    rows = read_results(raw)
    one_condition(rows)
    if {r["waf"] for r in rows} != {"modsecurity"}:
        raise ValueError("Supply a ModSecurity run.")
    by_id = {r["request_id"]: r for r in rows if r["execution_status"] == "SENT"}
    events, decisions = [], []
    seen_requests = set()
    digest = sha256(audit.read_bytes())
    for txid, sections in transactions(audit.read_text(encoding="utf-8", errors="replace")):
        rid_lines = [line.split(":", 1)[1].strip() for _, line in sections.get("B", [])
                     if line.lower().startswith("x-lab-request-id:")]
        if len(rid_lines) != 1 or rid_lines[0] not in by_id:
            continue
        rid = rid_lines[0]
        if rid in seen_requests:
            raise ValueError("Multiple audit transactions share a request ID; review instead of merging.")
        seen_requests.add(rid)
        row = by_id[rid]
        # Read only audit messages, never attacker-controlled request/response bodies.
        messages = [(n, line) for n, line in sections.get("H", []) if line.startswith("Message:")]
        blocked = any(re.search(r"^Message: Access denied with (?:code|connection)", line) for _,line in messages)
        reference = f"{audit.name}:transaction={txid};sha256={digest}"
        for number, line in messages:
            for rule_id in re.findall(r'\[id "(\d+)"\]', line):
                events.append(dict(run_id=row["run_id"], waf=row["waf"], test_id=row["test_id"],
                                   request_id=rid, transaction_id=txid, rule_id=rule_id,
                                   rule_group=rule_id[:3], intervention=str(blocked),
                                   evidence_reference=reference + f";line={number}"))
        if blocked:
            decisions.append({**{k: row[k] for k in DECISION_FIELDS[:4]},
                              "waf_action": "BLOCKED", "evidence_reference": reference,
                              "notes": "CANDIDATE: verify this transaction's real intervention before approving."})
    output.mkdir(parents=True, exist_ok=False)
    for name, fields, data in (("rule_events.csv", EVENT_FIELDS, events),
                               ("block_candidates.csv", DECISION_FIELDS, decisions)):
        with (output / name).open("x", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            writer.writerows(data)
    print(f"Matched {len(seen_requests)} transactions; review {len(decisions)} block candidates.")
    print("No ALLOWED decisions inferred. Keep raw evidence and review missing/ambiguous events.")

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--raw", required=True, type=Path)
    p.add_argument("--audit", required=True, type=Path)
    p.add_argument("--output-directory", required=True, type=Path)
    a = p.parse_args()
    try:
        extract(a.raw, a.audit, a.output_directory)
    except (ValueError, OSError) as exc:
        p.exit(2, f"{exc}\n")
if __name__ == "__main__":
    main()
