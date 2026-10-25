
from pathlib import Path
from collections import Counter, defaultdict
import csv
import json
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
OUT.mkdir(parents=True, exist_ok=True)

COMPARISON = ROOT / "Week_07/results/final/week6-comparison.csv"
MISSED = ROOT / "Week_07/results/final/naxsi-missed-detections.csv"
METRICS = ROOT / "Week_07/results/final/naxsi-metrics.json"

def read_csv(path):
    with path.open(newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))

def write_csv(path, rows, columns):
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)

comparison = read_csv(COMPARISON)
missed = read_csv(MISSED)
with METRICS.open() as f:
    expected = json.load(f)

print("Comparison rows:", len(comparison))
print("Missed-detection rows:", len(missed))

# Verify the stored reviewed classifications.
for waf in ("modsecurity", "naxsi"):
    counts = Counter(
        r[f"{waf}_classification"].strip().upper()
        for r in comparison
    )
    print(waf, dict(counts))
    assert len(comparison) == 1684, "Unexpected corpus size"
    assert not (set(counts) - {"TP", "TN", "FP", "FN"}), \
        "Unreviewed classifications found; investigate before charting"

    metrics_file = ROOT / f"Week_07/results/final/{waf}-metrics.json"
    with metrics_file.open() as f:
        m = json.load(f)

    for key in ("TP", "TN", "FP", "FN"):
        assert counts[key] == m[key], \
            f"{waf} {key}: comparison and metrics disagree"

assert len(missed) == expected["FN"], \
    "Missed-detection file does not match NAXSI FN total"
assert len({r["test_id"] for r in missed}) == len(missed), \
    "Duplicate test IDs found in missed-detection file"

print("PASS: Reviewed counts agree with saved metrics.")

# A. Detection rate by malicious attack category
groups = defaultdict(lambda: {
    "modsecurity_TP": 0, "modsecurity_FN": 0,
    "naxsi_TP": 0, "naxsi_FN": 0
})

for r in comparison:
    category = r["category"].strip().lower()
    for waf in ("modsecurity", "naxsi"):
        classification = r[f"{waf}_classification"].strip().upper()
        if classification in ("TP", "FN"):
            groups[category][f"{waf}_{classification}"] += 1

category_rows = []
for category, counts in sorted(groups.items()):
    row = {"category": category}
    for waf in ("modsecurity", "naxsi"):
        tp = counts[f"{waf}_TP"]
        fn = counts[f"{waf}_FN"]
        row[f"{waf}_TP"] = tp
        row[f"{waf}_FN"] = fn
        row[f"{waf}_detection_pct"] = round(
            100 * tp / (tp + fn), 2
        ) if tp + fn else None
    category_rows.append(row)

write_csv(
    OUT / "attack_category_detection.csv", category_rows,
    ["category", "modsecurity_TP", "modsecurity_FN",
     "modsecurity_detection_pct", "naxsi_TP",
     "naxsi_FN", "naxsi_detection_pct"]
)

labels = [r["category"] for r in category_rows]
x = list(range(len(labels)))
fig, ax = plt.subplots(figsize=(max(9, len(labels) * 1.8), 5))

ax.bar(
    [i - 0.2 for i in x],
    [r["modsecurity_detection_pct"] for r in category_rows],
    width=0.4, label="ModSecurity"
)
ax.bar(
    [i + 0.2 for i in x],
    [r["naxsi_detection_pct"] for r in category_rows],
    width=0.4, label="NAXSI"
)
ax.set_xticks(x, labels, rotation=25, ha="right")
ax.set_ylim(0, 110)
ax.set_ylabel("Detection rate (%)")
ax.set_title("Reviewed Malicious Detection by Attack Category")
ax.legend()
fig.tight_layout()
fig.savefig(OUT / "attack_category_detection.png", dpi=200)
plt.close(fig)

# B. NAXSI missed detections by attack category
by_category = Counter(
    r["category"].strip().lower() for r in missed
)

write_csv(
    OUT / "naxsi_fn_by_category.csv",
    [{"category": k, "false_negatives": v}
     for k, v in sorted(by_category.items())],
    ["category", "false_negatives"]
)

fig, ax = plt.subplots(figsize=(9, 5))
ax.bar(list(by_category), list(by_category.values()))
ax.set_title("NAXSI False Negatives by Attack Category")
ax.set_ylabel("False-negative requests")
ax.tick_params(axis="x", rotation=25)
fig.tight_layout()
fig.savefig(OUT / "naxsi_fn_by_category.png", dpi=200)
plt.close(fig)

# C. NAXSI missed detections by transformation
by_transformation = Counter(
    (r["transformation"].strip().lower() or "baseline")
    for r in missed
)

write_csv(
    OUT / "naxsi_fn_by_transformation.csv",
    [{"transformation": k, "false_negatives": v}
     for k, v in sorted(by_transformation.items())],
    ["transformation", "false_negatives"]
)

fig, ax = plt.subplots(figsize=(9, 5))
ax.bar(
    list(by_transformation),
    list(by_transformation.values())
)
ax.set_title("NAXSI False Negatives by Payload Transformation")
ax.set_ylabel("False-negative requests")
ax.tick_params(axis="x", rotation=30)
fig.tight_layout()
fig.savefig(OUT / "naxsi_fn_by_transformation.png", dpi=200)
plt.close(fig)

print("\nFalse negatives by category:")
for category, count in sorted(by_category.items()):
    print(f"  {category}: {count}")

print("\nFalse negatives by transformation:")
for transformation, count in sorted(by_transformation.items()):
    print(f"  {transformation}: {count}")

print("\nFiles generated in:", OUT)
print("Analysis completed successfully.")
