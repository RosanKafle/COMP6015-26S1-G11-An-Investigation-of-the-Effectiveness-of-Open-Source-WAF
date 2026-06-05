#!/usr/bin/env python3
"""Build the submission-ready DOCX report from current evidence files.

The script uses only the Python standard library. It reads the current CSV
evidence and writes a simple DOCX package directly, avoiding manual copying of
result percentages into the report.
"""

from __future__ import annotations

import csv
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
REPORT_DOCX = ROOT / "reports/final/COMP6015_Group11_WAF_Final_Report_SubmissionReady.docx"


def read_csv(relative_path: str) -> list[dict[str, str]]:
    path = ROOT / relative_path
    with path.open(newline="", encoding="utf-8-sig") as file_obj:
        return list(csv.DictReader(file_obj))


def as_float(value: str | float | int) -> float:
    if value in {"", None}:
        return 0.0
    return float(value)


def as_int(value: str | float | int) -> int:
    if value in {"", None}:
        return 0
    return int(float(value))


def fmt_pct(value: str | float | int) -> str:
    return f"{as_float(value):.2f}%"


def fmt_ms(value: str | float | int) -> str:
    return f"{as_float(value):.3f} ms"


def slug_label(value: str) -> str:
    labels = {
        "authorization_bypass": "Authorisation bypass",
        "brute_force": "Brute force",
        "csrf": "CSRF",
        "javascript": "JavaScript",
        "sqli": "SQLi",
        "weak_session_ids": "Weak session IDs",
        "xss": "XSS",
    }
    return labels.get(value, value.replace("_", " ").title())


def aggregate_attack_types(rows: list[dict[str, str]]) -> list[list[object]]:
    grouped: dict[str, dict[str, dict[str, int]]] = defaultdict(
        lambda: defaultdict(lambda: {"total": 0, "blocked": 0})
    )
    for row in rows:
        grouped[row["attack_type"]][row["environment"]]["total"] += as_int(row["total_requests"])
        grouped[row["attack_type"]][row["environment"]]["blocked"] += as_int(row["blocked_count"])

    attack_order = [
        "authorization_bypass",
        "brute_force",
        "csrf",
        "javascript",
        "sqli",
        "weak_session_ids",
        "xss",
    ]
    rows_out = []
    for attack_type in attack_order:
        mod = grouped[attack_type]["modsec"]
        cor = grouped[attack_type]["coraza"]
        mod_rate = (mod["blocked"] / mod["total"] * 100.0) if mod["total"] else 0.0
        cor_rate = (cor["blocked"] / cor["total"] * 100.0) if cor["total"] else 0.0
        rows_out.append(
            [
                slug_label(attack_type),
                mod["total"],
                mod["blocked"],
                f"{mod_rate:.2f}%",
                cor["total"],
                cor["blocked"],
                f"{cor_rate:.2f}%",
            ]
        )
    return rows_out


def run_summary_rows(
    final_summary: list[dict[str, str]],
    repetition: list[dict[str, str]],
) -> list[list[object]]:
    counts = {
        (row["environment"], row["phase"], row["load_level"]): row
        for row in repetition
    }
    rows_out = []
    for env in ["baseline", "modsec", "coraza"]:
        for phase, load in [("attack_only", "none"), ("mixed", "medium")]:
            summary = next(
                row
                for row in final_summary
                if row["environment"] == env and row["phase"] == phase and row["load_level"] == load
            )
            count_row = counts[(env, phase, load)]
            rows_out.append(
                [
                    env,
                    phase,
                    load,
                    count_row["attack_requests"],
                    count_row["benign_requests"],
                    fmt_pct(summary["detection_rate_percent"]),
                    fmt_pct(summary["false_positive_rate_percent"]),
                    fmt_ms(summary["avg_response_time_ms"]),
                    fmt_pct(summary["server_error_rate_percent"]),
                ]
            )
    return rows_out


def benign_rows(rows: list[dict[str, str]]) -> list[list[object]]:
    rows_out = []
    for row in rows:
        if row["phase"] != "mixed":
            continue
        rows_out.append(
            [
                row["environment"],
                row["total_benign_requests"],
                row["benign_allowed"],
                row["benign_blocked"],
                fmt_pct(row["false_positive_rate_percent"]),
                fmt_ms(row["avg_benign_response_time_ms"]),
            ]
        )
    return rows_out


def confusion_rows(rows: list[dict[str, str]]) -> list[list[object]]:
    rows_out = []
    for row in rows:
        if row["environment"] == "baseline":
            continue
        rows_out.append(
            [
                row["environment"],
                row["phase"],
                row["attack_rows"],
                row["benign_rows"],
                row["true_positive"],
                row["false_negative"],
                row["false_positive"],
                row["true_negative"],
                fmt_pct(as_float(row["recall"]) * 100.0),
                f"{as_float(row['precision']):.2f}",
            ]
        )
    return rows_out


def manual_sqli_rows(rows: list[dict[str, str]]) -> list[list[object]]:
    rows_out = []
    for env in ["baseline", "modsec", "coraza"]:
        row = next(item for item in rows if item["environment"] == env)
        rows_out.append(
            [
                env,
                row["sent"],
                row["clean_blocked"],
                row["allowed"],
                row["server_errors"],
                fmt_pct(row["clean_block_rate_percent"]),
                fmt_pct(row["allowed_rate_percent"]),
                fmt_pct(row["server_error_rate_percent"]),
            ]
        )
    return rows_out


def manual_sqli_gap_rows(rows: list[dict[str, str]]) -> list[list[object]]:
    labels = {
        "server_error_not_clean_block": "Server error, not a clean WAF block",
        "allowed_payload_possible_double_decoding_gap": "Allowed double-encoded payload",
        "allowed_payload_keyword_fragmentation": "Allowed keyword-fragmentation payload",
        "allowed_payload_auth_bypass_style_expression": "Allowed auth-bypass-style expression",
        "allowed_payload_symbolic_boolean_expression": "Allowed symbolic boolean expression",
    }
    grouped: dict[tuple[str, str], list[str]] = defaultdict(list)
    for row in rows:
        if row["environment"] in {"modsec", "coraza"}:
            grouped[(row["environment"], row["reason_category"])].append(row["payload_id"])

    rows_out = []
    reason_order = [
        "server_error_not_clean_block",
        "allowed_payload_possible_double_decoding_gap",
        "allowed_payload_keyword_fragmentation",
        "allowed_payload_auth_bypass_style_expression",
        "allowed_payload_symbolic_boolean_expression",
    ]
    for env in ["modsec", "coraza"]:
        for reason in reason_order:
            payloads = grouped.get((env, reason), [])
            if payloads:
                rows_out.append([env, labels[reason], len(payloads), ", ".join(payloads)])
    return rows_out


def csrf_rows(rows: list[dict[str, str]]) -> list[list[object]]:
    rows_out = []
    for env in ["baseline", "modsec", "coraza"]:
        row = next(item for item in rows if item["environment"] == env)
        rows_out.append(
            [
                env,
                row["sent"],
                row["clean_blocked"],
                row["allowed"],
                row["redirected"],
                fmt_pct(row["clean_block_rate_percent"]),
                fmt_pct(row["redirect_rate_percent"]),
            ]
        )
    return rows_out


def transport_summary_rows(rows: list[dict[str, str]]) -> list[list[object]]:
    return [
        [
            row["test_id"],
            row["transport"],
            row["method"],
            row["content_type"],
            row["evasion_type"],
            row["environment"],
            row["status_code"],
            row["result"],
        ]
        for row in rows
    ]


def xml_escape(value: object) -> str:
    text = str(value)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def text_runs(text: object) -> str:
    parts = str(text).split("\n")
    runs = []
    for index, part in enumerate(parts):
        if index:
            runs.append("<w:r><w:br/></w:r>")
        runs.append(f'<w:r><w:t xml:space="preserve">{xml_escape(part)}</w:t></w:r>')
    return "".join(runs)


def paragraph(text: object, style: str = "Normal") -> str:
    style_xml = f'<w:pPr><w:pStyle w:val="{style}"/></w:pPr>' if style != "Normal" else ""
    return f"<w:p>{style_xml}{text_runs(text)}</w:p>"


def bullet(text: object) -> str:
    return paragraph(f"- {text}", "Normal")


def table_xml(headers: list[str], rows: list[list[object]]) -> str:
    border = (
        '<w:tblBorders><w:top w:val="single" w:sz="4" w:space="0" w:color="888888"/>'
        '<w:left w:val="single" w:sz="4" w:space="0" w:color="888888"/>'
        '<w:bottom w:val="single" w:sz="4" w:space="0" w:color="888888"/>'
        '<w:right w:val="single" w:sz="4" w:space="0" w:color="888888"/>'
        '<w:insideH w:val="single" w:sz="4" w:space="0" w:color="888888"/>'
        '<w:insideV w:val="single" w:sz="4" w:space="0" w:color="888888"/></w:tblBorders>'
    )
    table = [f'<w:tbl><w:tblPr><w:tblW w:w="0" w:type="auto"/>{border}</w:tblPr>']

    def row_xml(values: list[object], header: bool = False) -> str:
        cells = []
        for value in values:
            shade = '<w:shd w:fill="E9EEF5"/>' if header else ""
            bold_start = "<w:b/>" if header else ""
            text = xml_escape(value)
            cells.append(
                "<w:tc>"
                f"<w:tcPr><w:tcW w:w=\"0\" w:type=\"auto\"/>{shade}</w:tcPr>"
                f"<w:p><w:r><w:rPr>{bold_start}</w:rPr><w:t xml:space=\"preserve\">{text}</w:t></w:r></w:p>"
                "</w:tc>"
            )
        return "<w:tr>" + "".join(cells) + "</w:tr>"

    table.append(row_xml(headers, header=True))
    for row in rows:
        table.append(row_xml(row))
    table.append("</w:tbl>")
    return "".join(table)


def make_blocks() -> list[str]:
    final_summary = read_csv("analysis/final/final_summary.csv")
    repetition = read_csv("analysis/final/final_repetition_summary.csv")
    attack_summary = read_csv("analysis/final/final_attack_type_summary.csv")
    benign_summary = read_csv("analysis/final/final_benign_summary.csv")
    confusion = read_csv("analysis/final/confusion_matrices.csv")
    sqli_expanded = read_csv("evidence/manual_validation/results/manual_sqli_expanded_overall_summary.csv")
    sqli_gaps = read_csv("evidence/manual_validation/results/manual_sqli_expanded_not_cleanly_blocked.csv")
    csrf_summary = read_csv("evidence/manual_validation/results/manual_csrf_overall_summary.csv")
    transport = read_csv("evidence/manual_validation/results/baseline_sqli_transport.csv")

    blocks: list[str] = []
    add = blocks.append
    add(paragraph("An Investigation into the Effectiveness of Open-Source Web Application Firewalls", "Title"))
    add(paragraph("COMP6015 Computer Science Project 1"))
    add(paragraph("Group COMP6015-26S1-G11"))
    add(paragraph("Supervisor: Mihai Lazarescu"))
    add(paragraph("Revised evidence-based report: 24 May 2026"))
    add(table_xml(
        ["Member", "Student ID", "Contribution summary"],
        [
            ["Sadaiba Kumar Acharya", "21647381", "Framework support, testing support and documentation review."],
            ["Bishal Giri", "22902243", "Separate XSS/NAXSI payload evidence contribution and result checking. The current quantitative claims use only evidence files present in this cleaned repository."],
            ["Pabin Gurung", "22343460", "Report consolidation, evidence mapping and submission preparation."],
            ["Roshan Kafle", "22393096", "Project support, review, documentation and result checking."],
        ],
    ))
    add(paragraph("Declaration of Originality", "Heading1"))
    add(paragraph("We declare that this report is our group work except where external tools, documentation, datasets or project evidence are identified. The claims in this revised version are based on the files currently present in the cleaned repository."))
    add(paragraph("Executive Summary", "Heading1"))
    add(paragraph("This project evaluates whether open-source Web Application Firewalls can improve protection for a vulnerable web application in a controlled laboratory setting. The target application was DVWA. The tested broad environments were a no-WAF baseline, ModSecurity and Coraza. NAXSI is not included in the structured evidence currently present in this submission package, so this report does not make a NAXSI performance claim."))
    add(paragraph("The automated broad evaluation shows that the no-WAF baseline blocked 0.00% of controlled attack requests. ModSecurity detected 34.84% in attack-only testing and 34.95% under medium mixed traffic. Coraza detected 34.77% in attack-only testing and 35.07% under medium mixed traffic. The mixed-traffic benign rows showed 0.00% observed false positives for both WAFs."))
    add(paragraph("The latest manual SQL injection evidence expands the SQLi validation set to 40 payloads. In that set, ModSecurity and Coraza each cleanly blocked 33 of 40 payloads, giving an 82.50% clean-block rate. Each also allowed 5 payloads and produced 2 server errors. The manual CSRF evidence used 5 password-change request variants. ModSecurity and Coraza each cleanly blocked 1 of 5 requests and redirected 4 of 5. The CSRF result should not be read as strong semantic CSRF detection because the one clean block was the special-character password case and likely reflects generic input filtering."))
    add(paragraph("The main conclusion is that ModSecurity and Coraza added useful protection against recognisable input-based attack patterns, especially SQLi and XSS-style patterns, but they did not solve logic-based weaknesses such as CSRF, authorisation bypass or weak session handling. A WAF is useful as defence in depth, not as a replacement for secure application code."))
    add(paragraph("1. Project Aim and Research Question", "Heading1"))
    add(paragraph("The aim of this project is to evaluate the practical effectiveness of open-source WAFs against common web attack patterns. The central research question is: can open-source WAFs provide measurable protection against common web application attacks while allowing normal traffic to continue?"))
    add(paragraph("The independent variable is the protection condition: baseline without WAF, ModSecurity or Coraza. The dependent variables are detection rate, false positive rate, response time, confusion-matrix counts and missed-attack categories. The controlled target application is DVWA."))
    add(paragraph("2. Evidence Scope", "Heading1"))
    add(paragraph("This report uses only evidence that is present in the cleaned repository. The main evidence paths are:"))
    for item in [
        "analysis/final/ - final automated summary tables.",
        "output/ - raw structured automated run folders.",
        "evidence/manual_validation/ - manual SQLi, CSRF and transport-placement evidence.",
        "framework/, tools/manual_validation/ and scripts/ - reproducibility code.",
        "docs/ - historical supporting evidence.",
    ]:
        add(bullet(item))
    add(paragraph("A separate XSS/NAXSI contribution was provided by a group member. However, the cleaned repository currently does not contain the source CSVs or screenshots for that package. To keep the report accurate, this version credits that contribution in the student details but does not include NAXSI performance figures as verified quantitative evidence. Those figures can be added later if the source evidence is added to the submission package."))
    add(paragraph("3. Background for Non-Technical Readers", "Heading1"))
    add(paragraph("A Web Application Firewall, or WAF, sits in front of a website and inspects web requests before the application handles them. It is useful when an attack has a recognisable pattern, such as SQL keywords or script text. It is weaker when the weakness is in application logic, such as a missing permission check or missing CSRF token."))
    add(table_xml(
        ["Term", "Plain meaning", "Why it matters in this report"],
        [
            ["WAF", "A filter placed in front of the web application.", "It is the protection being evaluated."],
            ["Payload", "The attack string placed in a request.", "Different payloads test different bypass methods."],
            ["Detection rate", "The share of malicious requests that were cleanly blocked.", "It shows security coverage, but not which attacks were missed."],
            ["False positive", "A normal request blocked by mistake.", "It shows whether security rules disrupt legitimate users."],
            ["Server error", "A 500-level error response.", "It is recorded, but it is not counted as a clean WAF block."],
            ["SQLi", "SQL injection, where input tries to alter a database query.", "It is one of the main attack families tested."],
            ["CSRF", "A request that tries to make a logged-in user perform an unwanted action.", "It usually needs application-side tokens, not only WAF filtering."],
            ["XSS", "Cross-site scripting, where input tries to make a browser run unwanted script.", "It is often pattern-based and therefore more visible to a WAF."],
        ],
    ))
    add(table_xml(
        ["Tool or component", "Role in the project"],
        [
            ["DVWA", "The deliberately vulnerable target application used for safe testing."],
            ["ModSecurity", "An open-source WAF used in the broad automated and manual validation evidence."],
            ["Coraza", "An open-source WAF used in the broad automated and manual validation evidence."],
            ["OWASP ZAP", "Proxy support for request capture and automated testing workflow."],
            ["Manual validation scripts", "Python scripts used to replay selected SQLi and CSRF cases and produce CSV summaries."],
        ],
    ))
    add(paragraph("4. Methodology", "Heading1"))
    add(paragraph("The automated framework sent controlled attack requests and benign mixed traffic to DVWA. A result was counted as a clean WAF block when the response code was 403, 406 or 501. A 200-level response was treated as allowed. Redirects and HTTP 500 server errors were recorded separately and were not counted as clean WAF detections."))
    add(paragraph("Two automated phases are used in the final evidence. The attack-only phase measures direct blocking behaviour against malicious requests. The mixed phase sends malicious and benign traffic together, which allows false positives and latency to be observed under a more realistic load pattern."))
    add(paragraph("5. Automated Broad Evaluation Results", "Heading1"))
    add(paragraph("5.1 Run-Level Summary", "Heading2"))
    add(table_xml(
        ["Environment", "Phase", "Load", "Attack rows", "Benign rows", "Detection rate", "False positive rate", "Average response time", "Server error rate"],
        run_summary_rows(final_summary, repetition),
    ))
    add(paragraph("Both WAFs improved detection compared with the baseline, but neither reached complete coverage. The mixed-traffic detection rates were close to the attack-only rates, which suggests that the medium benign load did not substantially reduce WAF detection in this evidence set."))
    add(paragraph("5.2 Attack-Type Detection", "Heading2"))
    add(table_xml(
        ["Attack type", "ModSecurity total", "ModSecurity blocked", "ModSecurity detection", "Coraza total", "Coraza blocked", "Coraza detection"],
        aggregate_attack_types(attack_summary),
    ))
    add(paragraph("The WAFs performed best against XSS-style and SQLi-style patterns. They did not meaningfully detect authorisation bypass, CSRF or weak session ID tests in the automated broad data. This is expected because those weaknesses often depend on application logic rather than a suspicious text pattern in the request."))
    add(paragraph("5.3 Benign Traffic and False Positives", "Heading2"))
    add(table_xml(
        ["Environment", "Benign rows", "Allowed", "Blocked", "False positive rate", "Average benign response time"],
        benign_rows(benign_summary),
    ))
    add(paragraph("No benign rows were blocked in the available mixed-traffic dataset. This supports a 0.00% observed false positive rate for the tested mixed workload, but it should not be treated as proof that false positives would never occur in production."))
    add(paragraph("5.4 Confusion-Matrix Summary", "Heading2"))
    add(table_xml(
        ["Environment", "Phase", "Attack rows", "Benign rows", "True positives", "False negatives", "False positives", "True negatives", "Recall", "Precision"],
        confusion_rows(confusion),
    ))
    add(paragraph("Precision is 1.00 in the WAF rows because there were no false positives in the available benign data. Recall is lower because many malicious requests were allowed or resulted in server errors rather than clean WAF blocks."))
    add(paragraph("6. Latest Manual Validation Tests", "Heading1"))
    add(paragraph("6.1 Expanded Manual SQLi Test: 40 Payloads", "Heading2"))
    add(paragraph("The newest SQLi validation file is evidence/manual_validation/payloads/manual_sqli_payloads_expanded.csv. It contains 40 payloads covering boolean-based SQLi, UNION probes, error-based probes, time-based probes, MySQL-specific strings, polyglots, authentication-bypass-style expressions and WAF-bypass variants."))
    add(table_xml(
        ["Environment", "Sent", "Clean blocked", "Allowed", "Server errors", "Clean-block rate", "Allowed rate", "Server-error rate"],
        manual_sqli_rows(sqli_expanded),
    ))
    add(paragraph("The expanded manual SQLi result is stronger than the broad automated SQLi headline because it uses targeted payloads that are easier for a signature-based WAF to recognise. Even so, both WAFs missed the same 5 allowed payloads and produced the same 2 server-error outcomes."))
    add(table_xml(
        ["Environment", "Not-clean outcome", "Count", "Payload IDs"],
        manual_sqli_gap_rows(sqli_gaps),
    ))
    add(paragraph("The most important SQLi gaps were double encoding, keyword fragmentation, auth-bypass-style expressions and symbolic boolean expressions. These are useful tuning targets because they identify families of payloads rather than only isolated examples."))
    add(paragraph("6.2 Manual CSRF Validation: 5 Requests", "Heading2"))
    add(paragraph("The manual CSRF evidence used 5 GET-based password-change request variants. CSRF is normally prevented by application-side anti-CSRF tokens and session controls, not by WAF pattern matching alone."))
    add(table_xml(
        ["Environment", "Sent", "Clean blocked", "Allowed", "Redirected", "Clean-block rate", "Redirect rate"],
        csrf_rows(csrf_summary),
    ))
    add(paragraph("For both WAFs, only CSRF003, the special-character password value, produced a clean 403 block. The other four requests were redirected. Redirects are useful to record, but they are not counted as clean WAF detections in this report."))
    add(paragraph("6.3 SQLi Transport-Placement Check", "Heading2"))
    add(paragraph("The transport-placement CSV is baseline-only evidence. It shows that the group considered SQLi placement in query parameters, POST form bodies, JSON bodies, headers and cookies. Because it is baseline-only, it is not used to claim WAF transport-specific detection."))
    add(table_xml(
        ["Test ID", "Transport", "Method", "Content type", "Evasion", "Environment", "Status", "Result"],
        transport_summary_rows(transport),
    ))
    add(paragraph("7. Interpretation of Missed Attacks", "Heading1"))
    add(paragraph("The missed attacks show where WAFs are weakest. Authorisation bypass, CSRF and weak session IDs were not meaningfully blocked in the automated broad evaluation because these attacks often look like ordinary requests unless the application enforces the correct business rule. SQLi and XSS had higher detection because their payloads usually contain recognisable syntax."))
    add(paragraph("Server errors are reported separately because they disrupt the request but do not prove that the WAF intentionally detected and blocked the payload. This distinction is important for fair reporting. A server error may indicate application fragility, proxy behaviour or an unhandled payload condition."))
    add(paragraph("8. Reproducibility", "Heading1"))
    add(paragraph("The repository is organised so a reader can trace conclusions back to evidence:"))
    for item in [
        "output/<environment>/<phase>/<load_level>/run_*/ contains raw automated runs.",
        "analysis/metrics_analysis.py generates automated summary CSVs from output/.",
        "tools/manual_validation/ contains the manual SQLi and CSRF runners and summary scripts.",
        "scripts/validate_structure.py checks the folder structure.",
        "scripts/list_experiment_coverage.py prints available and missing automated datasets.",
    ]:
        add(bullet(item))
    add(paragraph("Useful commands:"))
    add(paragraph("python3 scripts/validate_structure.py\npython3 scripts/list_experiment_coverage.py\npython3 analysis/metrics_analysis.py output/ --out analysis/final/final_summary.csv", "CodeBlock"))
    add(paragraph("9. Limitations", "Heading1"))
    for item in [
        "The target was DVWA in a controlled lab, not a production web application.",
        "The structured automated evidence covers Baseline, ModSecurity and Coraza only. NAXSI is not supported by the current structured evidence package.",
        "The mixed benign traffic produced 0.00% observed false positives, but a wider set of normal user workflows would be needed before making production claims.",
        "The manual SQLi and CSRF tests are attack-focused validation sets. They strengthen interpretation but do not replace the automated broad evaluation.",
        "Response-code classification is useful, but future work should link results to WAF audit logs for stronger rule-level proof.",
    ]:
        add(bullet(item))
    add(paragraph("10. Practical Recommendations", "Heading1"))
    for item in [
        "Use a WAF as defence in depth, not as the only security control.",
        "Fix SQL injection with prepared statements and input handling in the application.",
        "Fix XSS with output encoding, safe templates and content security controls.",
        "Fix CSRF with application-side tokens and session validation.",
        "Use rate limiting, lockout and monitoring for brute-force protection.",
        "Tune WAF rules against missed payload families such as double encoding and keyword fragmentation, then retest benign traffic.",
    ]:
        add(bullet(item))
    add(paragraph("11. Conclusion", "Heading1"))
    add(paragraph("The evidence supports a balanced conclusion. ModSecurity and Coraza improved protection compared with the no-WAF baseline, especially for recognisable SQLi, XSS, brute-force and JavaScript-related payload patterns. However, both WAFs missed important logic-based attack classes and some evasive SQLi payloads. The latest 40-payload manual SQLi validation shows that both WAFs can block many targeted SQLi payloads, but it also identifies clear tuning gaps."))
    add(paragraph("For small organisations, open-source WAFs can be cost-effective security layers, but they should be deployed with testing, monitoring and secure coding. The most useful outcome of this project is therefore not a single winning WAF. It is an evidence-based method for testing WAF behaviour, explaining misses and improving rules safely."))
    add(paragraph("References", "Heading1"))
    for item in [
        "OWASP. OWASP Top 10. https://owasp.org/Top10/",
        "OWASP Core Rule Set Project. OWASP CRS documentation. https://coreruleset.org/",
        "OWASP ZAP Project. ZAP documentation. https://www.zaproxy.org/docs/",
        "Digininja. Damn Vulnerable Web Application (DVWA). https://github.com/digininja/DVWA",
        "Coraza WAF Project. Coraza Web Application Firewall. https://github.com/corazawaf/coraza",
        "sqlmap project. Automatic SQL injection and database takeover tool. https://github.com/sqlmapproject/sqlmap",
        "PortSwigger Web Security Academy. Cross-site scripting guidance. https://portswigger.net/web-security/cross-site-scripting",
        "PayloadsAllTheThings. Payload reference repository. https://github.com/swisskyrepo/PayloadsAllTheThings",
    ]:
        add(bullet(item))
    add(paragraph("Appendix A: Evidence Map", "Heading1"))
    add(table_xml(
        ["Evidence item", "Path", "Claim supported"],
        [
            ["Automated final summaries", "analysis/final/*.csv", "Detection, false positives, latency, confusion matrices and attack-class results."],
            ["Raw automated runs", "output/", "Per-run request-level evidence and validation files."],
            ["Expanded manual SQLi", "evidence/manual_validation/payloads/manual_sqli_payloads_expanded.csv and results/manual_sqli_expanded_*.csv", "40-payload SQLi validation and missed-payload interpretation."],
            ["Manual CSRF", "evidence/manual_validation/payloads/manual_csrf_tests.csv and results/manual_csrf_*.csv", "5-request CSRF validation and redirect/block classification."],
            ["Manual scripts", "tools/manual_validation/", "Reproducibility of manual validation evidence."],
            ["Automated framework", "framework/", "Reproducibility of structured automated runs."],
        ],
    ))
    add(paragraph("Appendix B: Marker Guidance", "Heading1"))
    add(paragraph("The report is written for both technical and non-technical markers. The main technical terms are defined in context. Percentages are kept with the evidence tables so that claims can be checked directly against the CSV files. Unsupported claims from earlier drafts have been removed."))
    return blocks


def styles_xml() -> str:
    return """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/><w:rPr><w:sz w:val="22"/><w:szCs w:val="22"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:qFormat/><w:rPr><w:b/><w:sz w:val="36"/><w:szCs w:val="36"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/><w:pPr><w:spacing w:before="360" w:after="120"/></w:pPr><w:rPr><w:b/><w:sz w:val="28"/><w:szCs w:val="28"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/><w:pPr><w:spacing w:before="240" w:after="80"/></w:pPr><w:rPr><w:b/><w:sz w:val="24"/><w:szCs w:val="24"/></w:rPr></w:style>
  <w:style w:type="paragraph" w:styleId="CodeBlock"><w:name w:val="Code Block"/><w:basedOn w:val="Normal"/><w:pPr><w:ind w:left="360"/></w:pPr><w:rPr><w:rFonts w:ascii="Courier New" w:hAnsi="Courier New"/><w:sz w:val="20"/><w:szCs w:val="20"/></w:rPr></w:style>
</w:styles>"""


def document_xml(blocks: list[str]) -> str:
    body = "".join(blocks)
    return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <w:body>
    {body}
    <w:sectPr>
      <w:pgSz w:w="11906" w:h="16838"/>
      <w:pgMar w:top="1440" w:right="1080" w:bottom="1440" w:left="1080" w:header="720" w:footer="720" w:gutter="0"/>
    </w:sectPr>
  </w:body>
</w:document>"""


def write_docx(path: Path, blocks: list[str]) -> None:
    created = datetime(2026, 5, 24, tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
    content_types = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>"""
    rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"""
    word_rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>"""
    core = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:title>WAF Evaluation Final Report</dc:title>
  <dc:creator>COMP6015-26S1-G11</dc:creator>
  <cp:lastModifiedBy>COMP6015-26S1-G11</cp:lastModifiedBy>
  <dcterms:created xsi:type="dcterms:W3CDTF">{created}</dcterms:created>
  <dcterms:modified xsi:type="dcterms:W3CDTF">{created}</dcterms:modified>
</cp:coreProperties>"""
    app = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
  <Application>COMP6015 Report Builder</Application>
</Properties>"""
    with ZipFile(path, "w", ZIP_DEFLATED) as docx:
        docx.writestr("[Content_Types].xml", content_types)
        docx.writestr("_rels/.rels", rels)
        docx.writestr("word/_rels/document.xml.rels", word_rels)
        docx.writestr("word/document.xml", document_xml(blocks))
        docx.writestr("word/styles.xml", styles_xml())
        docx.writestr("docProps/core.xml", core)
        docx.writestr("docProps/app.xml", app)


def main() -> int:
    write_docx(REPORT_DOCX, make_blocks())
    print(f"Wrote {REPORT_DOCX.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
