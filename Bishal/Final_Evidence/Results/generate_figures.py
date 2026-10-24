from pathlib import Path
import json
import csv
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path.home() / "waf-semester2"

OUT = ROOT / "Final_Submission/Evidence/Results"
OUT.mkdir(parents=True, exist_ok=True)

paths = {
    "ModSecurity": ROOT / "Week_07/results/processed/modsecurity-week6/metrics.json",
    "NAXSI": ROOT / "Week_07/results/processed/naxsi-week6/metrics.json",
}

data = {}

for name, path in paths.items():
    with open(path) as f:
        data[name] = json.load(f)

    print(f"Loaded {name}: {path}")

def safe_div(a, b):
    return a / b if b else 0

rows = []

for name, m in data.items():
    tp, tn, fp, fn = (
        m["TP"], m["TN"], m["FP"], m["FN"]
    )

    rows.append({
        "WAF": name,
        "Precision": safe_div(tp, tp + fp),
        "Recall": safe_div(tp, tp + fn),
        "F1": safe_div(2 * tp, 2 * tp + fp + fn),
        "Specificity": safe_div(tn, tn + fp),
        "FPR": safe_div(fp, fp + tn),
        "FNR": safe_div(fn, fn + tp),
        "Accuracy": safe_div(tp + tn, tp + tn + fp + fn),
    })

    matrix = np.array([
        [tn, fp],
        [fn, tp]
    ])

    fig, ax = plt.subplots(figsize=(7, 5))
    im = ax.imshow(matrix, cmap="Blues")

    ax.set_xticks([0, 1], ["Allowed", "Blocked"])
    ax.set_yticks([0, 1], ["Normal", "Malicious"])
    ax.set_xlabel("WAF decision")
    ax.set_ylabel("Actual request category")
    ax.set_title(f"{name} — Reviewed Confusion Matrix")

    for i in range(2):
        for j in range(2):
            value = matrix[i, j]
            ax.text(
                j, i, str(value),
                ha="center", va="center",
                fontsize=16,
                color="white" if value > matrix.max() / 2 else "black"
            )

    fig.colorbar(im, ax=ax)
    fig.tight_layout()

    filename = OUT / f"{name.lower()}_confusion_matrix.png"
    fig.savefig(filename, dpi=200)
    plt.close(fig)

    print(f"Saved: {filename}")

metrics_path = OUT / "performance_metrics.csv"

with open(metrics_path, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)

metrics = ["Precision", "Recall", "F1", "Specificity"]

x = np.arange(len(metrics))
width = 0.35

fig, ax = plt.subplots(figsize=(9, 5))

for offset, row in zip(
    [-width / 2, width / 2],
    rows
):
    values = [row[k] * 100 for k in metrics]

    ax.bar(
        x + offset,
        values,
        width,
        label=row["WAF"]
    )

ax.set_xticks(x, metrics)
ax.set_ylabel("Percentage (%)")
ax.set_ylim(0, 110)
ax.set_title("ModSecurity vs NAXSI — Performance Comparison")
ax.legend()
ax.grid(axis="y", alpha=0.2)

fig.tight_layout()
fig.savefig(
    OUT / "waf_performance_comparison.png",
    dpi=200
)
plt.close(fig)

print("\nPerformance metrics:")
for row in rows:
    print(row)

print("\nAll figures generated successfully.")
