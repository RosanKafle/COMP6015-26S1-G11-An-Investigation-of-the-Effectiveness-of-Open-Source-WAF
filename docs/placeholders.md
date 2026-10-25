# Placeholders and unverified items

- Example IPs, hostnames and ports describe the prior report; verify them in the VMs.
- Empty .env.example secrets require real local values; no credentials are supplied.
- Environment and WAF inventories remain NOT VERIFIED.
- lab_reviewed and scanner_lab_reviewed remain false until the researcher verifies them.
- scanner_ids is empty until the installed ZAP's rules and their lab-only behaviour are reviewed.
- Generated Week 6/7 variants are REQUIRES_REVIEW, not proven semantic equivalents.
- Imported legacy ZAP requests are REQUIRES_REVIEW until labels and fields are checked.
- comparison_template.csv is a template, never an experiment input.
- No new results or report findings are supplied. Any result template carries:
  PLACEHOLDER - replace with actual experimental results after execution.

The marker command and traversal fixture are actual laboratory test inputs, not
fabricated results. They require the real fixture and application calibration.
historical/final_report contains existing evidence, explicitly separated from new runs.
