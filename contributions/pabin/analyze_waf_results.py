
import json
import csv
import matplotlib.pyplot as plt

# Read the previously reported WAF results
with open("reported_aggregates.json", "r") as file:
    data = json.load(file)

results = []

# Calculate the detection metrics for each WAF
for experiment in data["experiments"]:
    experiment_name = experiment["id"]

    for waf in experiment["records"]:
        tp = waf["tp"]
        fn = waf["fn"]
        fp = waf["fp"]
        tn = waf["tn"]

        if min(tp, fn, fp, tn) < 0:
            raise ValueError("Counts cannot be negative")

        malicious = tp + fn
        benign = fp + tn
        total = malicious + benign

        expected = (1564, 120) if experiment_name == "A" else (87, 24)

        if experiment_name not in ["A", "B"]:
            raise ValueError("Unknown experiment")

        if (malicious, benign) != expected:
            raise ValueError("Experiment totals do not match")

        recall = tp / malicious * 100 if malicious else 0
        precision = tp / (tp + fp) * 100 if tp + fp else 0
        false_positive_rate = fp / benign * 100 if benign else 0
        accuracy = (tp + tn) / total * 100 if total else 0

        result = {
            "experiment": experiment_name,
            "waf": waf["waf"],
            "tp": tp,
            "fn": fn,
            "fp": fp,
            "tn": tn,
            "recall_pct": round(recall, 2),
            "precision_pct": round(precision, 2),
            "false_positive_rate_pct": round(false_positive_rate, 2),
            "accuracy_pct": round(accuracy, 2)
        }

        results.append(result)

        print(experiment_name, waf["waf"],
              "Recall:", round(recall, 2),
              "FPR:", round(false_positive_rate, 2))

# Save results to a CSV file
columns = [
    "experiment", "waf", "tp", "fn", "fp", "tn",
    "recall_pct", "precision_pct",
    "false_positive_rate_pct", "accuracy_pct"
]

with open("waf_comparison.csv", "w", newline="") as file:
    writer = csv.DictWriter(file, fieldnames=columns)
    writer.writeheader()
    writer.writerows(results)

# Create separate charts for Experiment A and Experiment B
fig, axes = plt.subplots(1, 2, figsize=(11, 5))

for index, experiment_name in enumerate(["A", "B"]):
    experiment_results = [
        r for r in results if r["experiment"] == experiment_name
    ]

    names = [r["waf"] for r in experiment_results]
    recall_values = [r["recall_pct"] for r in experiment_results]
    fpr_values = [r["false_positive_rate_pct"] for r in experiment_results]

    positions = range(len(names))

    axes[index].bar(
        [p - 0.2 for p in positions],
        recall_values, width=0.4, label="Recall"
    )
    axes[index].bar(
        [p + 0.2 for p in positions],
        fpr_values, width=0.4, label="False positive rate"
    )

    axes[index].set_xticks(list(positions))
    axes[index].set_xticklabels(names)
    axes[index].set_ylim(0, 110)
    axes[index].set_title("Experiment " + experiment_name)
    axes[index].set_ylabel("Percentage")
    axes[index].legend()

plt.suptitle("WAF Comparison - Previously Reported Results")
plt.tight_layout()
plt.savefig("waf_detection_chart.png")
plt.close()

print("CSV and chart created successfully")
