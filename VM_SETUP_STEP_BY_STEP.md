# Step by step setup using your previous Kali and Ubuntu VMs

This guide improves your existing semester setup. **Kali runs Python and ZAP.
Ubuntu runs the existing Apache/ModSecurity, Nginx/NAXSI and DVWA.** Do not install
the superseded container stack or run the generator on Ubuntu.

Your final report records Kali 192.168.56.10, Ubuntu 192.168.56.20, DVWA /DVWA/ and
ZAP on Kali loopback port 8080. Verify these values; the VM was not inspected live.
Read one step at a time. Commands marked Kali run in Kali Terminal; commands marked
Ubuntu run in Ubuntu Terminal. Stop at a failed checkpoint.

## 1. Preserve both existing VMs

1. Shut down Kali and Ubuntu normally.
2. In VirtualBox, take a snapshot of each named Before Semester 4 continuation.
3. Keep the original project files and existing database.
4. Confirm the two VMs share the same host-only network.
5. NAT may stay connected for downloading dependencies only. Before active scans,
   disconnect NAT on both VMs and ensure the host does not route the subnet outward.
6. Boot both VMs.

The ModSecurity and NAXSI conditions can use the same Ubuntu endpoint sequentially.
Only the active, verified WAF condition should be tested at a time.

## 2. Record the current systems

On **both VMs**, create a private evidence folder and record actual configuration:

~~~bash
umask 077
EVIDENCE="$HOME/sem4-setup-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir "$EVIDENCE"
printf '%s\n' "$EVIDENCE" > "$HOME/sem4-latest-setup.txt"
cat /etc/os-release > "$EVIDENCE/os-release.txt"
hostnamectl > "$EVIDENCE/hostname.txt"
ip -br address > "$EVIDENCE/interfaces.txt"
ip route > "$EVIDENCE/routes.txt"
sudo ss -lntp > "$EVIDENCE/listeners.txt"
~~~

On **Ubuntu**:

~~~bash
sudo apache2ctl -S > "$EVIDENCE/apache-vhosts.txt" 2>&1
sudo apache2ctl -M > "$EVIDENCE/apache-modules.txt" 2>&1
sudo apache2ctl -t -D DUMP_INCLUDES > "$EVIDENCE/apache-includes.txt" 2>&1
sudo nginx -T > "$EVIDENCE/nginx-config.txt" 2>&1
sudo systemctl status apache2 nginx mariadb --no-pager > "$EVIDENCE/services.txt" 2>&1
for name in apache2 nginx modsecurity; do
    if sudo test -d "/etc/$name"; then
        sudo tar -czf "$EVIDENCE/$name-before.tar.gz" -C /etc "$name"
    fi
done
sudo chown -R "$(id -u):$(id -g)" "$EVIDENCE"
~~~

A nonzero status for a stopped service is not a reason to reinstall it.
Read the files and identify the actual Apache DVWA VirtualHost, ModSecurity
configuration/rule includes and Nginx proxy configuration. If NAXSI is absent,
record that prerequisite; do not pretend the comparative condition is ready.

## 3. Copy this continuation onto Kali

Keep your old zap-waf-framework directory untouched. Copy the Windows folder
waf-semester2 into Kali's home directory using your existing transfer method.

For a VirtualBox shared folder, configure the Windows parent Files directory as
a read-only auto-mounted share named waf_transfer. On **Kali**:

~~~bash
ls /media/sf_waf_transfer
~~~

If permission is denied, add your Kali user to the existing Guest Additions group:

~~~bash
sudo usermod -aG vboxsf "$USER"
~~~

Log out and back in. If the share is not mounted, use your existing working
SFTP/shared-folder mechanism. Then, on **Kali**:

~~~bash
test ! -e "$HOME/waf-semester2" && cp -r /media/sf_waf_transfer/waf-semester2 "$HOME/"
cd "$HOME/waf-semester2"
export REPO="$PWD"
ls -d Week_0*
~~~

If a prior copy exists, preserve it under a different name before transferring this
revision. Do not merge old and revised week folders by blindly overwriting files.

## 4. Prepare Python on Kali

~~~bash
python3 -c 'import sys; assert sys.version_info >= (3,11), "Python 3.11+ required"; print(sys.version)'
~~~

If it is older, provision Python 3.11+ in a separate interpreter/venv before continuing;
do not replace system Python in the old VM. With a compatible Python:

~~~bash
sudo apt update
sudo apt install python3-venv
cd "$REPO"
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python -m pip freeze > requirements-local.txt
~~~

The tests use temporary loopback fixtures, not the Ubuntu WAF. Preserve the installed
ZAP version/add-ons; do not upgrade ZAP or CRS between paired experiments.

## 5. Restore and verify the existing ModSecurity condition on Ubuntu

The report's condition is Apache/ModSecurity serving /DVWA/ on the host-only
address. In the later NAXSI condition Apache may have moved to port 8080.
Use the backups and outputs from Step 2 to identify the state you have.

On **Ubuntu**:

~~~bash
sudo apache2ctl -M | grep security2
sudo apache2ctl -S
sudo grep -n 'Listen' /etc/apache2/ports.conf
sudo grep -R -nE 'SecRuleEngine|SecAuditEngine|SecAuditLog|SecAuditLogParts' /etc/modsecurity /etc/apache2
~~~

If the original ModSecurity condition is already working on port 80, preserve its
routing and CRS includes. Verify SecRuleEngine On in the effective DVWA scope.

If Nginx currently owns port 80 and Apache is the backend, restore your known
ModSecurity snapshot/configuration. Alternatively, after Step 2 backups, make the
following targeted changes using nano:

1. Stop Nginx and Apache before changing their listeners.
2. In /etc/apache2/ports.conf restore the original port-80 listener.
3. In the actual DVWA VirtualHost restore its port-80 binding.
4. Set SecRuleEngine On in that VirtualHost; remove any more-specific Off override.
5. Keep existing DocumentRoot, database, CRS version and rule includes.
6. Validate Apache, then start it.

~~~bash
sudo systemctl stop nginx apache2
sudo nano /etc/apache2/ports.conf
# Enter the actual DVWA site path identified by apache2ctl -S:
read -r -p 'Actual DVWA VirtualHost file: ' DVWA_SITE
sudo nano "$DVWA_SITE"
sudo apache2ctl configtest && sudo systemctl start apache2
~~~

Do not execute the stop/edit branch if your ModSecurity condition is already correct.
In nano save with Ctrl+O, Enter; exit Ctrl+X. Keep the host-only network isolated.

**Checkpoint:** Apache reports Syntax OK; ModSecurity and CRS are loaded exactly
once; Firefox on Kali opens the actual Ubuntu DVWA login page. A 403 needs inspection
of the real WAF rule; it is not proof of a successful application/session check.

## 6. Improve evidence logging without changing the rule set

On **Ubuntu**, edit the existing ModSecurity configuration identified in Step 2.
Preserve the original rule includes and thresholds. Enable full native audit evidence:

~~~apache
SecAuditEngine On
SecAuditLogType Serial
SecAuditLogFormat Native
SecAuditLogParts ABFHZ
~~~

Retain the real SecAuditLog path, for example /var/log/apache2/modsec_audit.log.
Do not add another conflicting SecAuditLog declaration. Native parts B and H are
required by the parser. Audit logs contain sensitive headers; keep private copies.

Add one Apache logging configuration on **Ubuntu**:

~~~bash
sudo nano /etc/apache2/conf-available/sem4-evidence.conf
~~~

Paste:

~~~apache
LogFormat "LAB_BACKEND local_port=%{local}p rid=%{X-Lab-Request-ID}i status=%>s request=%r" sem4_evidence
GlobalLog /var/log/apache2/sem4-requests.log sem4_evidence
~~~

Then:

~~~bash
sudo a2enconf sem4-evidence
sudo apache2ctl configtest && sudo systemctl reload apache2
~~~

Apache GlobalLog requires a supported Apache version. With NAXSI later proxying to
Apache port 8080, that log's local_port=8080 proves backend arrival, not authentication
or successful exploitation. ModSecurity port-80 entries alone do not prove passage
past its enforcement stage. See the
[Apache logging reference](https://httpd.apache.org/docs/2.4/mod/mod_log_config.html).

## 7. Prepare private settings and start the existing ZAP on Kali

On **Kali**:

~~~bash
cd "$REPO"
cp -n .env.example .env
chmod 600 .env
nano .env
~~~

Enter the actual private Ubuntu URL for the appropriate WAF fields, actual DVWA
username/password, and a new API key. Keep LAB_COOKIE empty for password login.
Generate a key without placing it in terminal history:

~~~bash
python - <<'PY'
from pathlib import Path
import secrets
p = Path(".env")
text = p.read_text()
lines = []
for line in text.splitlines():
    if line == "ZAP_API_KEY=":
        line = "ZAP_API_KEY=" + secrets.token_hex(24)
    lines.append(line)
p.write_text("\n".join(lines) + "\n")
p.chmod(0o600)
print("API key prepared in private .env; not displayed.")
PY
~~~

Keep the existing ZAP installation. Close another ZAP instance using port 8080
after saving its previous session. Use a dedicated working profile, preserving the
old default profile/session. The profile needs the installed spider, active scanner
and Replacer add-ons; verify availability before scanning.

Create a private ZAP API configuration from .env, then launch ZAP in the foreground:

~~~bash
mkdir -p "$HOME/sem4-zap"
python - <<'PY'
from pathlib import Path
import sys
sys.path.insert(0, "Week_02/scripts")
from config_loader import environment
p = Path.home() / "sem4-zap/api.properties"
key = environment(Path(".env"))["ZAP_API_KEY"]
if not key:
    raise SystemExit("Set ZAP_API_KEY first.")
p.write_text("api.key=" + key + "\napi.disablekey=false\n")
p.chmod(0o600)
PY
/usr/share/zaproxy/zap.sh -daemon -host 127.0.0.1 -port 8080 \
    -dir "$HOME/sem4-zap" -configfile "$HOME/sem4-zap/api.properties"
~~~

Use the actual existing launch path if ZAP was installed elsewhere. Keep that
terminal open and use a second Kali terminal for the following steps. API access
remains on Kali loopback. Unlike the old report command, the API key is not disabled.
[ZAP API documentation](https://www.zaproxy.org/docs/desktop/start/features/api/).

## 8. Create local configurations for the snapshots

In the second **Kali** terminal:

~~~bash
export REPO="$HOME/waf-semester2"
cd "$REPO"
source .venv/bin/activate
python - <<'PY'
import json, sys
from pathlib import Path
sys.path.insert(0, "Week_02/scripts")
from config_loader import environment
values = environment(Path(".env"))
for n in range(1,8):
    folder = Path(f"Week_{n:02}/config")
    env = json.loads((folder/"environment.example.json").read_text())
    for component,key in [("dvwa","TARGET_URL"),("modsecurity","MODSECURITY_URL"),
                          ("naxsi","NAXSI_URL"),("zap","ZAP_URL")]:
        env["components"][component] = values[key]
    path = folder/"environment.json"
    if not path.exists():
        path.write_text(json.dumps(env,indent=2)+"\n")
    if n >= 2:
        base = json.loads((folder/"test_config.json").read_text())
        for waf in ("modsecurity","naxsi"):
            path = folder/f"local-{waf}.json"
            if not path.exists():
                config = dict(base, waf_name=waf, target_url=values[waf.upper()+"_URL"],
                              results_directory=f"results/raw/{waf}")
                path.write_text(json.dumps(config,indent=2)+"\n")
print("Configs prepared. Existing local files were preserved; review them if topology changed.")
PY
~~~

The examples keep lab_reviewed=false and scanner_lab_reviewed=false. Do not mark
them true until the corresponding checkpoints have actually been verified.

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

## 19. Stop and resume safely

Stop the dedicated foreground ZAP daemon with Ctrl+C in its terminal after work.
Shut down the VMs normally. Keep Kali run data and copied evidence separately before
reverting an Ubuntu snapshot. Do not reset the existing DVWA database.

In a new Kali terminal:

~~~bash
export REPO="$HOME/waf-semester2"
cd "$REPO"
source .venv/bin/activate
~~~

Restart ZAP using Step 7's existing private profile/config file. Do not source .env
as Bash; pass --env-file .env. Restore run-path variables from actual saved folders.
Record which Ubuntu condition is active before any --execute command.

## Troubleshooting and honest limits

| Symptom | Action |
|---|---|
| Week 1 both WAF URLs respond | Same sequential listener does not identify the active engine; verify Ubuntu mode/configuration. |
| DVWA login fails | Verify URL, current credentials, Low security and actual form; inspect real WAF logs. |
| Normal 403 | Inspect rule reasons and headers/session. Preserve initial condition before any documented tuning. |
| ZAP connection refused | Verify daemon and Kali loopback port; do not point ZAP_URL at Ubuntu. |
| ZAP API error | Verify key, installed API/add-ons and private ZAP logs; --list-scanners is read-only. |
| ZAP context exists | Save/close old session and use the dedicated empty working session. |
| Nginx unknown directive | Resolve the existing module/build; do not remove the WAF to bypass the error. |
| NAXSI request blocked by ModSecurity | Correct the backend engine scope; this is not a valid single-WAF comparison. |
| Output exists | Use a unique output name; preserve raw data. |
| Digest differs | Cases, order, review flags or selection changed; start a new matched comparison. |
| UNKNOWN results | Review real WAF/backend evidence. Status codes do not settle the classification. |

No VM configuration, actual WAF run, screenshot, log or detection rate was fabricated.
All examples require real verification. See docs/placeholders.md and PROJECT_STATUS.md.
