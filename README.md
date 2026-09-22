# An Investigation of the Effectiveness of Open Source Web Application Firewalls

**Role:** WAF and Infrastructure Engineer. **Continuation:** Semester 4, the second
project semester; the requested repository name waf-semester2 is retained.

This repository improves the previous semester's existing **Kali Python/ZAP ->
Ubuntu ModSecurity or NAXSI -> DVWA** setup. It preserves the original pipeline
entry names, inherited payload families, authenticated browser-style traffic and
600-request mixed workload. It does not require an Ubuntu-only replacement lab.

Start with [VM_SETUP_STEP_BY_STEP.md](VM_SETUP_STEP_BY_STEP.md).
[COMMANDS.md](COMMANDS.md) gives the week-by-week Kali commands.
[REVISION_RECORD.md](REVISION_RECORD.md) identifies the archived superseded version.
[docs/continuity_mapping.md](docs/continuity_mapping.md) maps old code/report sections
to actual improvements.

## Incremental development

| Week | Improvement to the inherited project |
|---|---|
| Week 1 | Review existing environment, source lineage and architecture |
| Week 2 | Standardise methodology, configuration and classification rules |
| Week 3 | Freeze inherited test templates into a seeded, labelled mixed corpus |
| Week 4 | Improve original replay/mixed/ZAP pipelines, login and evidence collection |
| Week 5 | Run exactly the same pipeline/corpus through both WAF conditions |
| Week 6 | Generate reviewed variations retaining parent test IDs |
| Week 7 | Analyse missed detections, false positives, observed rules and latency |

Every Week folder is self-contained. Added capabilities are retained in later
snapshots; no runtime imports depend on another Week directory. See
[docs/snapshot_lineage.md](docs/snapshot_lineage.md) for actual file changes.

## Setup and original entry points

Use Python 3.11+ on **Kali**, reusing the installed ZAP and the Ubuntu services.
Set up a virtual environment and install requirements.txt. Copy .env.example to
.env and enter actual private lab URLs/credentials. Never commit .env.

After following the VM guide's network and service checks, on Kali:

~~~bash
cd "$HOME/waf-semester2"
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
~~~

From Week_04 onward:

- zap_active_mixed_modsecurity.py: inherited authenticated mixed replay, now repeatable.
- automate_modsecurity_sqli.py: retained SQLi replay task using reviewed cases.
- run_all_modsecurity_tests.py: attack-only batch; distinct from the mixed cohort.
- zap_active_master_modsecurity.py: bounded, scoped ZAP spider/active-scan pipeline.
- Week_05 onward: scripts/run_comparison.py and zap_active_mixed_naxsi.py reuse that engine.

Execution defaults to planning. Actual runs require --execute and lab_reviewed=true.
Scanner execution additionally requires reviewed scanner IDs, isolated networking
and scanner_lab_reviewed=true. See the guide for real session and enforcement checks.

## Inputs and evidence

The mixed corpus has 120 normal requests plus 120 each of SQLi, XSS, command injection
and traversal. It is generated from inherited templates, not from invented outcomes.
Repeated templates do not represent independent payloads. Deliberate method/fixture
changes are documented in each snapshot's config/inherited_test_templates.json.

Week_06/07 contain candidate variants; they remain REQUIRES_REVIEW until validated.
Raw run files are immutable. HTTP status alone leaves WAF action UNKNOWN.
Review real WAF/backend evidence before classification or metrics.

historical/final_report contains unchanged existing CSVs with source hashes.
They are previous-semester observations, not new execution. The 600-row mixed cohort
and 1,200-request attack batch must remain separate.

## Honest project status

This is a catch-up implementation made now. No historical timestamps, results, logs,
screenshots or Git dates were manufactured. No actual Kali/Ubuntu WAF experiment has
been executed by this implementation here. Unit fixtures use temporary loopback
servers and are not lab findings. PROJECT_STATUS.md remains evidence-based.

Concurrent throughput/load experiments and expanded OWASP-specific fixtures remain
future work. The code records client response times and can summarise them; it
does not claim isolated WAF overhead or successful exploitation from allowance.
