
import csv
from collections import Counter

# Read the reviewed Experiment A results
with open("source_comparison.csv", newline="") as file:
    records = list(csv.DictReader(file))

# Select NAXSI false negatives
misses = []

for row in records:
    if row["naxsi_classification"] == "FN":
        misses.append(row)

# Count misses by category and payload variant
categories = Counter(row["category"] for row in misses)
variants = Counter(row["variant"] for row in misses)

print("NAXSI Missed Detection Analysis")
print("Total false negatives:", len(misses))

print("\nMisses by attack category:")
for category, count in sorted(categories.items()):
    print(category, count)

print("\nMisses by payload variant:")
for variant, count in sorted(variants.items()):
    print(variant, count)

# Check against the reported Experiment A totals
expected_categories = {
    "xss": 120,
    "sqli": 92,
    "path_traversal": 42
}

expected_variants = {
    "doubleenc": 212,
    "baseline": 42
}

if len(misses) != 254:
    raise ValueError("False-negative total does not match")

if dict(categories) != expected_categories:
    raise ValueError("Category counts do not match")

if dict(variants) != expected_variants:
    raise ValueError("Variant counts do not match")

print("\nVALIDATION PASSED")
print("All missed-detection counts match the reported results.")
