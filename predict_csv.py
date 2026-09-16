import os
import joblib
import pandas as pd
import numpy as np


# ============================================================
# AI-NET CSV PREDICTION
# ============================================================

MODEL_PATH = "models/random_forest_model.pkl"
SCALER_PATH = "models/scaler.pkl"
FEATURES_PATH = "model_features.txt"


print("\n" + "=" * 70)
print("AI-NET CSV NETWORK TRAFFIC DETECTION")
print("=" * 70)


# ------------------------------------------------------------
# 1. LOAD MODEL
# ------------------------------------------------------------

if not os.path.exists(MODEL_PATH):
    print("ERROR: Model not found:", MODEL_PATH)
    exit()

if not os.path.exists(SCALER_PATH):
    print("ERROR: Scaler not found:", SCALER_PATH)
    exit()

if not os.path.exists(FEATURES_PATH):
    print("ERROR: Feature file not found:", FEATURES_PATH)
    exit()


model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)


# ------------------------------------------------------------
# 2. LOAD FEATURES
# ------------------------------------------------------------

features = []

with open(FEATURES_PATH, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()

        if not line:
            continue

        # Remove numbering such as "1. "
        if ". " in line:
            first_part, remaining = line.split(". ", 1)

            if first_part.isdigit():
                line = remaining.strip()

        # Ignore Label
        if line.lower() != "label":
            features.append(line)


print("\nEXPECTED FEATURES:")
for i, feature in enumerate(features, 1):
    print(f"{i}. {feature}")

print(f"\nTotal expected features: {len(features)}")


# ------------------------------------------------------------
# 3. CHECK FEATURE COUNT
# ------------------------------------------------------------

if len(features) != 10:
    print("\nERROR: Expected exactly 10 model features.")
    print("Found:", len(features))
    exit()


# ------------------------------------------------------------
# 4. GET CSV PATH
# ------------------------------------------------------------

print("\n" + "=" * 70)

csv_path = input("Enter CSV file path: ").strip().strip('"')


if not os.path.exists(csv_path):
    print("\nERROR: CSV file not found.")
    print("Path entered:")
    print(csv_path)
    exit()


# ------------------------------------------------------------
# 5. LOAD CSV
# ------------------------------------------------------------

print("\nLoading CSV...")

try:
    df = pd.read_csv(csv_path)
    df.columns = df.columns.str.strip()
except Exception as e:
    print("\nERROR while reading CSV:")
    print(e)
    exit()


print("CSV loaded successfully.")
print("Rows:", len(df))
print("Columns:", len(df.columns))


# ------------------------------------------------------------
# 6. CHECK FEATURES
# ------------------------------------------------------------

missing_features = [
    feature for feature in features
    if feature not in df.columns
]


if missing_features:
    print("\nERROR: Missing required features:")

    for feature in missing_features:
        print("-", feature)

    print("\nActual CSV columns:")
    for column in df.columns:
        print("-", column)

    exit()


print("\nAll 10 required features found.")


# ------------------------------------------------------------
# 7. PREPARE DATA
# ------------------------------------------------------------

X = df[features].copy()


# Convert everything to numeric
for column in features:
    X[column] = pd.to_numeric(X[column], errors="coerce")


# Replace infinity
X = X.replace([np.inf, -np.inf], np.nan)


# Fill missing values using median
for column in features:
    median_value = X[column].median()

    if pd.isna(median_value):
        median_value = 0

    X[column] = X[column].fillna(median_value)


# ------------------------------------------------------------
# 8. SCALE FEATURES
# ------------------------------------------------------------

print("Scaling features...")

try:
    X_scaled = scaler.transform(X)
except Exception as e:
    print("\nERROR during scaling:")
    print(e)
    exit()


# ------------------------------------------------------------
# 9. PREDICT
# ------------------------------------------------------------

print("Running AI detection...\n")

try:
    predictions = model.predict(X_scaled)
    probabilities = model.predict_proba(X_scaled)

except Exception as e:
    print("\nERROR during prediction:")
    print(e)
    exit()


# ------------------------------------------------------------
# 10. RESULTS
# ------------------------------------------------------------

print("=" * 70)
print("AI-NET DETECTION RESULTS")
print("=" * 70)


# Model classes
classes = model.classes_

print("\nPrediction distribution:")

unique, counts = np.unique(predictions, return_counts=True)

for value, count in zip(unique, counts):
    print(f"Class {value}: {count} rows")


# ------------------------------------------------------------
# 11. BENIGN / DDOS COUNTS
# ------------------------------------------------------------

benign_count = np.sum(predictions == 0)
ddos_count = np.sum(predictions == 1)

total = len(predictions)

print("\n" + "-" * 70)

print(f"Total traffic analyzed : {total}")
print(f"BENIGN traffic         : {benign_count}")
print(f"DDoS traffic           : {ddos_count}")

if total > 0:
    print(f"BENIGN percentage      : {(benign_count / total) * 100:.2f}%")
    print(f"DDoS percentage        : {(ddos_count / total) * 100:.2f}%")


# ------------------------------------------------------------
# 12. AVERAGE CONFIDENCE
# ------------------------------------------------------------

max_probabilities = np.max(probabilities, axis=1)

average_confidence = np.mean(max_probabilities) * 100

print(f"\nAverage model confidence: {average_confidence:.2f}%")


# ------------------------------------------------------------
# 13. SAVE RESULTS
# ------------------------------------------------------------

result_df = df.copy()

result_df["AI_Net_Prediction"] = predictions
result_df["AI_Net_Confidence"] = max_probabilities


output_path = "logs/csv_predictions.csv"

os.makedirs("logs", exist_ok=True)

result_df.to_csv(output_path, index=False)


print("\nResults saved to:")
print(output_path)


# ------------------------------------------------------------
# 14. FINAL MESSAGE
# ------------------------------------------------------------

print("\n" + "=" * 70)
print("CSV ANALYSIS COMPLETE")
print("=" * 70)