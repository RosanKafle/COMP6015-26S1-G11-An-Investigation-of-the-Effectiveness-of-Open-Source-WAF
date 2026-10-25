
import csv
import sys
from collections import Counter

# Select the CSV file
filename = "source_comparison.csv"

if len(sys.argv) > 1:
    filename = sys.argv[1]

print("Checking file:", filename)

# Read the CSV data
with open(filename, "r", newline="", encoding="utf-8-sig") as file:
    reader = csv.DictReader(file)
    columns = reader.fieldnames
    records = list(reader)

print("Total records:", len(records))

# Check required columns
required_columns = [
    "test_id",
    "category",
    "variant",
    "modsecurity_classification",
    "naxsi_classification"
]

for column in required_columns:
    if column not in columns:
        raise ValueError("Missing column: " + column)

# Check missing IDs
test_ids = []

for record in records:
    test_id = record["test_id"].strip()

    if test_id == "":
        raise ValueError("Missing test ID")

    test_ids.append(test_id)

# Check duplicate IDs
if len(test_ids) != len(set(test_ids)):
    raise ValueError("Duplicate test IDs found")

# Check total records
if len(records) != 1684:
    raise ValueError("Incorrect number of records")

# Expected results from the group report
expected_results = {
    "ModSecurity": {
        "TP": 1564,
        "TN": 109,
        "FP": 11,
        "FN": 0
    },
    "NAXSI": {
        "TP": 1310,
        "TN": 108,
        "FP": 12,
        "FN": 254
    }
}

# Check ModSecurity and NAXSI results
waf_columns = {
    "ModSecurity": "modsecurity_classification",
    "NAXSI": "naxsi_classification"
}

for waf in waf_columns:
    column = waf_columns[waf]
    classifications = []

    for record in records:
        classification = record[column].strip().upper()
        classifications.append(classification)

    counts = Counter(classifications)

    # Check unexpected values
    for label in counts:
        if label not in ["TP", "TN", "FP", "FN"]:
            raise ValueError("Invalid classification: " + label)

    print("\nWAF:", waf)

    for label in ["TP", "TN", "FP", "FN"]:
        actual = counts[label]
        expected = expected_results[waf][label]

        print(label, "Actual:", actual, "Expected:", expected)

        if actual != expected:
            raise ValueError(waf + " result does not match: " + label)

print("\nVALIDATION PASSED")
print("All records and reported classification totals matched.")
