# Kali commands for the cumulative weekly improvements

Follow VM_SETUP_STEP_BY_STEP.md Steps 1–8 first. All execution commands below
run on Kali; server preparation blocks are explicitly marked Ubuntu. The guide
is the authoritative setup procedure. Start in $HOME/waf-semester2 with .venv active.

## 9. Week 1: review the inherited infrastructure

On **Kali**, load the API key into the process for the Week 1 check:

~~~bash
export ZAP_API_KEY="$(python -c 'import sys; from pathlib import Path; sys.path.insert(0,"Week_02/scripts"); from config_loader import environment; print(environment(Path(".env"))["ZAP_API_KEY"])')"
python Week_01/scripts/check_environment.py --config Week_01/config/environment.json
~~~

Review Week_01/outputs/environment_check.csv. If both WAF URLs are identical,
reachability only proves the active listener responds. It does not prove both WAFs
are active. Verify each condition separately. For subsequent checks use a unique
--output filename. Complete the environment inventory with real observations.

## 10. Week 2: standardise the inherited methodology

On **Kali**:

~~~bash
python Week_02/scripts/config_loader.py \
    --config Week_02/config/local-modsecurity.json --env-file .env
~~~

Read Week_02/docs/methodology.md and classification_rules.md. Record the previous
rule versions/thresholds and intended repetitions. Validation sends no attack traffic.

## 11. Week 3: review the inherited cases and marker fixture

On **Ubuntu**, create the harmless file for traversal tests, only if absent:

~~~bash
if [ ! -e /tmp/waf-lab-marker.txt ]; then
    printf '%s\n' 'WAF_LAB_TRAVERSAL_MARKER' | sudo tee /tmp/waf-lab-marker.txt > /dev/null
    sudo chmod 644 /tmp/waf-lab-marker.txt
fi
cat /tmp/waf-lab-marker.txt
~~~

On **Kali**:

~~~bash
python Week_03/scripts/test_loader.py
~~~

Review the five category CSVs and config/inherited_test_templates.json.
There are 600 input rows and 120 per category; many repeat templates.
The new command method/fixture targets are documented changes.

In Firefox on Kali, log in to DVWA through Ubuntu and set DVWA Security to Low.
Verify a normal name in Reflected XSS and the existing file1.php inclusion page.
Calibrate attack intent on the same application in a separately recorded WAF-off
condition, then restore ModSecurity On. Do not count those calibration requests as
the matched 600-row baseline. Verify POST handling for the command-injection form.

To prepare a separate smaller corpus without modifying the supplied one:

~~~bash
python Week_03/scripts/build_mixed_corpus.py --per-class 5 --seed 2026 \
    --output Week_03/traffic/pilot
~~~

Optional legacy SQLi capture import (input stays unchanged; outputs need review):

~~~bash
read -r -p 'Path to your previous traffic/sqli_raw.json: ' OLD_CAPTURE
read -r -p 'Original private target base URL recorded in that capture: ' OLD_TARGET
python Week_03/scripts/import_zap_capture.py --input "$OLD_CAPTURE" \
    --source-target "$OLD_TARGET" --output Week_03/traffic/imported-sqli/cases.csv
~~~

Review labels and fields before changing REQUIRES_REVIEW to APPROVED.
Never load an unreviewed capture directly into an unrestricted replay command.

## 12. Week 4: improve and exercise the inherited pipelines

On **Kali**, after real lab/case review, edit only the local ModSecurity configuration:

~~~bash
nano Week_04/config/local-modsecurity.json
~~~

Set lab_reviewed to true. Leave transport as zap and auth_mode as password.
Use the original mixed-script name, first as a plan:

~~~bash
python Week_04/zap_active_mixed_modsecurity.py \
    --config Week_04/config/local-modsecurity.json --env-file .env --category normal --limit 5
~~~

Execute the five normal requests when the plan is correct:

~~~bash
python Week_04/zap_active_mixed_modsecurity.py \
    --config Week_04/config/local-modsecurity.json --env-file .env \
    --category normal --limit 5 --execute
~~~

The script checks ZAP, logs into DVWA using its current token, sends requests through
ZAP and checks session health. Login failure prevents measured traffic. Requests
are not silently retried. Inspect completion.json and the real captured responses.
A login page or unexpected redirect is not a successful application test.

The inherited SQLi and attack-batch entry points are retained:

~~~bash
python Week_04/automate_modsecurity_sqli.py \
    --config Week_04/config/local-modsecurity.json --env-file .env
python Week_04/run_all_modsecurity_tests.py \
    --config Week_04/config/local-modsecurity.json --env-file .env
~~~

Those are plans. Add --execute only for the actual intended experiment. The attack
batch excludes normal traffic and is not the mixed cohort.

### Separate ZAP spider/active-scanning pipeline

On both VMs disconnect NAT and verify routes before active scanning. Use an empty
dedicated ZAP session. Keep the host-only network and confirm DVWA remains reachable.
The original active-master entry point now inventories installed scanner rules:

~~~bash
python Week_04/zap_active_master_modsecurity.py \
    --config Week_04/config/local-modsecurity.json --env-file .env --list-scanners
~~~

Select the intended installed SQLi/XSS/traversal/command scanner IDs in scanner_ids.
Exclude out-of-band/callback or external-service-dependent rules. Review actual rule
behaviour and lab isolation, then set scanner_lab_reviewed=true. Do not enable all
scanners simply to make the program run.

~~~bash
python Week_04/zap_active_master_modsecurity.py \
    --config Week_04/config/local-modsecurity.json --env-file .env
python Week_04/zap_active_master_modsecurity.py \
    --config Week_04/config/local-modsecurity.json --env-file .env --execute
~~~

This is a bounded exploratory scan, separate from the reproducible mixed comparison.
It uses an exact DVWA context, current session cookies scoped to that context, and
its own scan-message IDs. Authentication loss stops it. Read cleanup warnings; close
the dedicated ZAP session if rule cleanup failed. Do not interpret scanner alerts
as WAF detections or automatically label every scan message malicious.

## 13. Week 5: collect the ModSecurity baseline

Verify Ubuntu is back in the ModSecurity condition, then on **Kali**:

~~~bash
nano Week_05/config/local-modsecurity.json
nano Week_05/config/local-naxsi.json
~~~

Review both and set lab_reviewed=true only for verified conditions. Same URL for
sequential conditions is valid; the code does not switch the server for you.

~~~bash
python Week_05/scripts/run_comparison.py --waf modsecurity \
    --config Week_05/config/local-modsecurity.json --env-file .env --category all
python Week_05/scripts/run_comparison.py --waf modsecurity \
    --config Week_05/config/local-modsecurity.json --env-file .env --category all --execute
read -r -p 'Full path to the actual ModSecurity run folder: ' MOD_RUN
export MOD_RUN
DIGEST="$(python -c 'import json,os; from pathlib import Path; print(json.loads((Path(os.environ["MOD_RUN"])/"manifest.json").read_text())["test_set_sha256"])')"
~~~

Copy real ModSecurity audit and Apache access logs before switching condition.
On **Ubuntu**, use the actual existing audit path:

~~~bash
read -r -p 'A unique evidence label for this run: ' RUN_LABEL
mkdir -p "$HOME/sem4-run-evidence/$RUN_LABEL"
read -r -p 'Actual ModSecurity audit log path: ' AUDIT_LOG
sudo install -m 600 -o "$USER" "$AUDIT_LOG" "$HOME/sem4-run-evidence/$RUN_LABEL/modsecurity-audit.log"
sudo install -m 600 -o "$USER" /var/log/apache2/sem4-requests.log "$HOME/sem4-run-evidence/$RUN_LABEL/apache-requests.log"
sudo apache2ctl -S > "$HOME/sem4-run-evidence/$RUN_LABEL/apache-vhosts.txt" 2>&1
sudo apache2ctl -t -D DUMP_INCLUDES > "$HOME/sem4-run-evidence/$RUN_LABEL/apache-includes.txt" 2>&1
~~~

Also save copies of the actual rule/configuration files and versions, privately.
On **Kali**, transfer through your existing SSH account:

~~~bash
read -r -p 'Ubuntu SSH user@private-IP: ' UBUNTU_SSH
read -r -p 'The evidence label used on Ubuntu: ' RUN_LABEL
mkdir -p Week_05/logs
scp -r "$UBUNTU_SSH:~/sem4-run-evidence/$RUN_LABEL" Week_05/logs/
~~~

Take an Ubuntu snapshot named with the actual verified ModSecurity condition.
Preserve Kali results independently before reverting any VM snapshot.

## 14. Reuse the existing NAXSI configuration on Ubuntu

Use your known NAXSI snapshot if available, keeping DVWA version/database/security
consistent. Otherwise restore the previous Nginx/NAXSI configuration from your
existing semester files after inspecting it; do not install a replacement stack.

The inherited NAXSI arrangement uses Nginx port 80 -> Apache backend port 8080.
On **Ubuntu**, after backups, if converting the working ModSecurity condition:

1. Stop Apache/Nginx.
2. Change only the Apache HTTP listener to 127.0.0.1:8080.
3. Change the actual DVWA VirtualHost to 127.0.0.1:8080.
4. Set SecRuleEngine Off inside that backend VirtualHost, checking for overriding
   Directory settings. Do not unload the module or delete CRS.
5. In the existing Nginx server, retain NAXSI/core rules and verified score thresholds,
   use enforcing mode (no LearningMode), and proxy to http://127.0.0.1:8080.
6. Retain DVWA /DVWA/ and its database. Do not reset them.

~~~bash
sudo systemctl stop nginx apache2
sudo nano /etc/apache2/ports.conf
read -r -p 'Actual DVWA VirtualHost file: ' DVWA_SITE
sudo nano "$DVWA_SITE"
read -r -p 'Existing NAXSI Nginx server configuration file: ' NAXSI_SITE
sudo nano "$NAXSI_SITE"
sudo apache2ctl configtest
sudo nginx -t
~~~

Only when both tests pass:

~~~bash
sudo systemctl start apache2
sudo systemctl start nginx
sudo ss -lntp
~~~

Unknown NAXSI directives or a missing module are an unresolved prerequisite, not a
reason to remove WAF directives. Preserve the installed version/build settings.
The [NAXSI configuration guide](https://wargio.github.io/naxsi/basic-configuration.html)
describes the engine/learning controls; use your actual previously deployed rules.

Add a log_format once in the Nginx http scope (not inside server/location):

~~~nginx
log_format sem4 '$time_iso8601 rid=$http_x_lab_request_id nginx_rid=$request_id status=$status upstream=$upstream_status request=$request';
~~~

In the existing NAXSI server/location use:

~~~nginx
access_log /var/log/nginx/sem4-access.log sem4;
error_log /var/log/nginx/sem4-error.log info;
# Inside the proxied location:
proxy_set_header X-Lab-Request-ID $http_x_lab_request_id;
~~~

Validate/reload Nginx. Match external rid to the Nginx/NAXSI transaction where the
installed version supports it. Preserve UNKNOWN when correlation is ambiguous.
Apache backend arrival is not by itself proof of an authenticated endpoint response.

**Checkpoint:** Kali can open/login to the same DVWA through NAXSI, NAXSI is enforcing,
and its backend does not impose a second enforcing ModSecurity layer.

## 15. Run the same Week 5 corpus through NAXSI

On **Kali**, keep the actual MOD_RUN and DIGEST from Step 13:

~~~bash
python Week_05/scripts/run_comparison.py --waf naxsi \
    --config Week_05/config/local-naxsi.json --env-file .env --category all \
    --expect-test-set-sha256 "$DIGEST" --execute
read -r -p 'Full path to the actual NAXSI run folder: ' NAXSI_RUN
export NAXSI_RUN
~~~

The program establishes a fresh DVWA session for the new condition. Collect the
actual Nginx access/error logs, Apache backend log and nginx -T output using the
same private Ubuntu-copy/Kali-scp process as Step 13, under a new evidence label.
Record differences in rules and any application changes. Do not tune between paired
conditions without declaring a new experiment.

## 16. Review real evidence and merge

On **Kali**, identify the actual copied ModSecurity audit file and parse it:

~~~bash
read -r -p 'Copied ModSecurity audit file: ' MOD_AUDIT
python Week_05/scripts/parse_modsecurity_audit.py --raw "$MOD_RUN/results.csv" \
    --audit "$MOD_AUDIT" --output-directory Week_05/results/processed/modsecurity-audit-review
~~~

This produces rule_events.csv and block_candidates.csv. Inspect the actual cited
transactions. Replace a candidate note with your own review rationale only after
verification; unreviewed candidate notes are rejected by apply_evidence.py.

Create final reviewed decision CSVs with this header:

~~~text
run_id,waf,test_id,request_id,waf_action,evidence_reference,notes
~~~

Use BLOCKED only for a matching real WAF intervention. Use ALLOWED only with evidence
that the request passed this WAF to the intended authenticated application.
Leave ambiguous/error/skipped cases unreviewed. Never infer a detected rule category
from the expected traffic label. NAXSI decisions require its own real log evidence.

~~~bash
read -r -p 'Reviewed ModSecurity decision CSV: ' MOD_DECISIONS
read -r -p 'Reviewed NAXSI decision CSV: ' NAXSI_DECISIONS
MOD_REVIEWED="Week_05/results/processed/$(basename "$MOD_RUN")-reviewed.csv"
NAXSI_REVIEWED="Week_05/results/processed/$(basename "$NAXSI_RUN")-reviewed.csv"
python Week_05/scripts/apply_evidence.py --raw "$MOD_RUN/results.csv" \
    --evidence "$MOD_DECISIONS" --output "$MOD_REVIEWED"
python Week_05/scripts/apply_evidence.py --raw "$NAXSI_RUN/results.csv" \
    --evidence "$NAXSI_DECISIONS" --output "$NAXSI_REVIEWED"
python Week_05/analysis/merge_results.py --modsecurity "$MOD_REVIEWED" \
    --naxsi "$NAXSI_REVIEWED" --output Week_05/results/processed/comparison.csv
~~~

Use new output names for subsequent runs. Never edit raw CSVs.

## 17. Week 6: improve the same payloads with controlled variations

On **Kali**:

~~~bash
python Week_06/scripts/test_loader.py --include-variants \
    --output Week_06/outputs/variant_inventory.csv
~~~

The supplied 1,084 variant candidates derive from the 600-row inherited baseline.
They remain REQUIRES_REVIEW. Validate semantic equivalence and actual encoding
before changing selected rows to APPROVED. Unreviewed rows are skipped.

If regeneration is necessary, move the existing candidate file outside variants/:

~~~bash
mv Week_06/test_cases/variants/generated_variants.csv \
    "Week_06/outputs/variants-before-review-$(date -u +%Y%m%dT%H%M%SZ).csv"
python Week_06/scripts/generate_variants.py
~~~

Review both Week 6 configs, restore/verify the ModSecurity condition and run:

~~~bash
python Week_06/scripts/run_comparison.py --waf modsecurity \
    --config Week_06/config/local-modsecurity.json --env-file .env --category all --include-variants
python Week_06/scripts/run_comparison.py --waf modsecurity \
    --config Week_06/config/local-modsecurity.json --env-file .env \
    --category all --include-variants --execute
read -r -p 'Actual Week 6 ModSecurity run folder: ' MOD_RUN
export MOD_RUN
DIGEST="$(python -c 'import json,os; from pathlib import Path; print(json.loads((Path(os.environ["MOD_RUN"])/"manifest.json").read_text())["test_set_sha256"])')"
~~~

Collect its logs before switching. Restore/verify NAXSI, then:

~~~bash
python Week_06/scripts/run_comparison.py --waf naxsi \
    --config Week_06/config/local-naxsi.json --env-file .env --category all \
    --include-variants --expect-test-set-sha256 "$DIGEST" --execute
read -r -p 'Actual Week 6 NAXSI run folder: ' NAXSI_RUN
export NAXSI_RUN
~~~

Repeat Step 16 with Week_06 output paths and the new run/evidence files.
Do not reuse Week_05 decision files or its corpus digest for this changed corpus.

## 18. Week 7: analysis of actual reviewed data

On **Kali**, set INPUT to one real reviewed Week 5 or Week 6 CSV:

~~~bash
read -r -p 'Actual reviewed ModSecurity or NAXSI CSV: ' INPUT
ANALYSIS="Week_07/results/processed/analysis-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$ANALYSIS"
python Week_07/analysis/metrics.py --input "$INPUT" --output "$ANALYSIS/metrics.json"
python Week_07/analysis/category_summary.py --input "$INPUT" --output "$ANALYSIS/categories.csv"
python Week_07/analysis/confusion_matrix.py --input "$INPUT" --output "$ANALYSIS/confusion.csv"
python Week_07/analysis/missed_detection_analysis.py --input "$INPUT" --output "$ANALYSIS/missed_detections.csv"
python Week_07/analysis/latency_summary.py --input "$INPUT" --output "$ANALYSIS/latency.json"
python Week_07/analysis/generate_analysis_report.py --input "$INPUT" \
    --output "Week_07/reports/analysis-$(date -u +%Y%m%dT%H%M%SZ).md"
~~~

For ModSecurity only, supply the parser's rule_events.csv from that same run:

~~~bash
read -r -p 'Actual rule_events.csv for this ModSecurity run: ' RULE_EVENTS
python Week_07/analysis/rule_analysis.py --input "$INPUT" --events "$RULE_EVENTS" \
    --output-directory "$ANALYSIS/rules"
~~~

Repeat separately for each WAF/run. NAXSI score/rule semantics are not CRS categories.
Use a Week 6 run to analyse baseline/variant pairs. Unknowns remain separate.
No real result input means no generated analysis. Timing summaries include proxy,
network and application effects; they are not concurrent performance benchmarks.

