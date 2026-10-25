
from pathlib import Path
from collections import defaultdict, Counter
import csv
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[4]
OUT = Path(__file__).resolve().parent
OUT.mkdir(parents=True, exist_ok=True)

def read_csv(path):
    with path.open(newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))

comparison = read_csv(
    ROOT / "experiments/modsecurity-naxsi/implementation/results/final/week6-comparison.csv"
)

validation = read_csv(
    ROOT / "experiments/modsecurity-naxsi/reviewed-data/outputs/variant_semantic_validation.csv"
)

transformations = {
    row["test_id"]: row["transformation"].strip().lower()
    for row in validation
}

summary = defaultdict(Counter)
unmapped = set()

for row in comparison:
    test_id = row["test_id"]
    variant = row["variant"].strip().lower()

    if variant == "baseline":
        transformation = "baseline"
    elif test_id in transformations:
        transformation = transformations[test_id]
    else:
        transformation = "unmapped"
        unmapped.add(test_id)

    category = row["category"].strip().lower()

    for waf in ("modsecurity", "naxsi"):
        classification = row[
            f"{waf}_classification"
        ].strip().upper()

        summary[
            (transformation, category, waf)
        ][classification] += 1

rows = []

for (transformation, category, waf), counts in sorted(summary.items()):
    tp = counts["TP"]
    fn = counts["FN"]
    total = tp + fn

    rows.append({
        "transformation": transformation,
        "category": category,
        "waf": waf,
        "TP": tp,
        "FN": fn,
        "malicious_total": total,
        "detection_rate_pct":
            round(100 * tp / total, 2) if total else "",
    })

out_csv = OUT / "transformation_detection_detail.csv"

with out_csv.open("w", newline="") as f:
    writer = csv.DictWriter(
        f, fieldnames=list(rows[0].keys())
    )
    writer.writeheader()
    writer.writerows(rows)

print("===== TRANSFORMATION SUMMARY =====")

types = sorted(set(r["transformation"] for r in rows))

for transformation in types:
    print(f"\n{transformation.upper()}")

    for waf in ("modsecurity", "naxsi"):
        selected = [
            r for r in rows
            if r["transformation"] == transformation
            and r["waf"] == waf
        ]

        tp = sum(r["TP"] for r in selected)
        fn = sum(r["FN"] for r in selected)

        if tp + fn:
            print(
                f"  {waf}: TP={tp}, FN={fn}, "
                f"Detection={100*tp/(tp+fn):.2f}%"
            )

print("\nUnmapped request IDs:", len(unmapped))

if unmapped:
    print("WARNING: Some variants could not be mapped.")
    print("Examples:", sorted(unmapped)[:10])

# Generate a detection-rate comparison chart.
plotted_types = [t for t in types if t != "unmapped"]

fig, ax = plt.subplots(
    figsize=(max(10, len(plotted_types) * 1.4), 5)
)

for waf, offset in [("modsecurity", -0.2), ("naxsi", 0.2)]:
    values = []

    for transformation in plotted_types:
        selected = [
            r for r in rows
            if r["transformation"] == transformation
            and r["waf"] == waf
        ]

        tp = sum(r["TP"] for r in selected)
        fn = sum(r["FN"] for r in selected)

        values.append(
            100 * tp / (tp + fn) if tp + fn else 0
        )

    ax.bar(
        [i + offset for i in range(len(plotted_types))],
        values,
        width=0.4,
        label=waf
    )

ax.set_xticks(
    range(len(plotted_types)),
    plotted_types,
    rotation=30,
    ha="right"
)

ax.set_ylabel("Malicious detection rate (%)")
ax.set_ylim(0, 110)
ax.set_title("WAF Detection by Payload Transformation")
ax.legend()

fig.tight_layout()

fig.savefig(
    OUT / "transformation_detection_comparison.png",
    dpi=200
)
plt.close(fig)

print("\nAnalysis completed.")
print("Saved CSV:", out_csv)
print("Saved chart:",
      OUT / "transformation_detection_comparison.png")
