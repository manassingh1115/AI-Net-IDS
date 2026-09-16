import os
import glob
import json
import joblib
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix
)


# ============================================================
# AI-NET - NETWORK INTRUSION DETECTION
# BENIGN vs DDoS
# ============================================================

print("\n" + "=" * 70)
print("AI-NET NETWORK INTRUSION DETECTION MODEL")
print("=" * 70)


# ============================================================
# EXACT 10 FEATURES USED BY THE FLASK APPLICATION
# ============================================================

FEATURES = [
    "Avg Bwd Segment Size",
    "Packet Length Variance",
    "Bwd Packet Length Max",
    "Max Packet Length",
    "Bwd Packet Length Std",
    "Packet Length Std",
    "Average Packet Size",
    "Subflow Fwd Packets",
    "act_data_pkt_fwd",
    "Bwd Packet Length Mean"
]


print("\nFEATURES:")
for i, feature in enumerate(FEATURES, 1):
    print(f"{i}. {feature}")


# ============================================================
# FIND CSV FILES
# ============================================================

print("\n" + "=" * 70)
print("SEARCHING FOR DATASET")
print("=" * 70)

csv_files = []

search_locations = [
    "data/raw",
    "data"
]

for location in search_locations:

    if os.path.exists(location):

        files = glob.glob(
            os.path.join(
                location,
                "**",
                "*.csv"
            ),
            recursive=True
        )

        for file in files:

            if file not in csv_files:
                csv_files.append(file)


if not csv_files:

    print("\nERROR: No CSV files found.")
    print("Put the CIC-IDS2017 CSV files inside data/raw/")
    raise SystemExit(1)


print(f"\nFound {len(csv_files)} CSV files.")


# ============================================================
# LOAD DATA
# ============================================================

all_data = []


for file in csv_files:

    print("\nLoading:")
    print(file)

    try:

        df = pd.read_csv(
            file,
            low_memory=False
        )

        # Remove whitespace from column names
        df.columns = (
            df.columns
            .astype(str)
            .str.strip()
        )

        print(
            "Rows:",
            len(df),
            "| Columns:",
            len(df.columns)
        )

        # ----------------------------------------------------
        # FIND LABEL COLUMN
        # ----------------------------------------------------

        label_column = None

        for column in df.columns:

            normalized = (
                str(column)
                .strip()
                .lower()
                .replace(" ", "")
                .replace("_", "")
            )

            if normalized == "label":

                label_column = column
                break


        if label_column is None:

            print("No Label column -> skipped")
            continue


        # ----------------------------------------------------
        # CHECK REQUIRED FEATURES
        # ----------------------------------------------------

        missing = [
            feature
            for feature in FEATURES
            if feature not in df.columns
        ]

        if missing:

            print("Missing required features -> skipped")
            continue


        # ----------------------------------------------------
        # SELECT ONLY BENIGN AND DDOS
        # ----------------------------------------------------

        labels = (
            df[label_column]
            .astype(str)
            .str.strip()
            .str.upper()
        )

        mask = labels.isin(
            [
                "BENIGN",
                "DDOS"
            ]
        )

        selected = df.loc[
            mask,
            FEATURES + [label_column]
        ].copy()


        if selected.empty:

            print("No BENIGN/DDoS rows -> skipped")
            continue


        # ----------------------------------------------------
        # CONVERT LABEL
        # ----------------------------------------------------

        selected["Target"] = (
            selected[label_column]
            .astype(str)
            .str.strip()
            .str.upper()
            .map(
                {
                    "BENIGN": 0,
                    "DDOS": 1
                }
            )
        )


        selected.drop(
            columns=[label_column],
            inplace=True
        )


        all_data.append(selected)


        print(
            "Added:",
            len(selected),
            "rows"
        )


    except Exception as error:

        print(
            "Could not load file:",
            error
        )


# ============================================================
# COMBINE DATA
# ============================================================

if not all_data:

    print("\nERROR: No usable data found.")
    raise SystemExit(1)


data = pd.concat(
    all_data,
    ignore_index=True
)


print("\n" + "=" * 70)
print("DATASET COMBINED")
print("=" * 70)

print(
    "Total rows:",
    len(data)
)

print(
    "Total columns:",
    len(data.columns)
)


# ============================================================
# CLEAN DATA
# ============================================================

X = data[FEATURES].copy()
y = data["Target"].copy()


print("\nCleaning numeric features...")


for feature in FEATURES:

    X[feature] = pd.to_numeric(
        X[feature],
        errors="coerce"
    )


# Replace infinity
X.replace(
    [np.inf, -np.inf],
    np.nan,
    inplace=True
)


# Replace NaN using median
for feature in FEATURES:

    median = X[feature].median()

    if pd.isna(median):
        median = 0

    X[feature] = X[feature].fillna(
        median
    )


# Remove any remaining invalid values
valid = np.isfinite(
    X.to_numpy()
).all(axis=1)


X = X.loc[
    valid
].reset_index(drop=True)


y = y.loc[
    valid
].reset_index(drop=True)


print(
    "Rows after cleaning:",
    len(X)
)

print(
    "Features:",
    X.shape[1]
)


# ============================================================
# VERIFY FEATURES
# ============================================================

if X.shape[1] != 10:

    print(
        "\nERROR: Expected exactly 10 features."
    )

    raise SystemExit(1)


print(
    "\nFEATURE COUNT VERIFIED: 10"
)


# ============================================================
# CLASS DISTRIBUTION
# ============================================================

print("\nCLASS DISTRIBUTION:")

print(
    y.value_counts()
)


# ============================================================
# IMPORTANT:
# REDUCE DATASET SIZE FOR RAM
# ============================================================

MAX_TRAINING_ROWS = 300000


if len(X) > MAX_TRAINING_ROWS:

    print("\n" + "=" * 70)
    print("LARGE DATASET DETECTED")
    print("=" * 70)

    print(
        "Original rows:",
        len(X)
    )

    print(
        "Training rows:",
        MAX_TRAINING_ROWS
    )

    print(
        "\nCreating balanced random sample..."
    )


    # Add target temporarily
    temp = X.copy()

    temp["Target"] = y.values


    # Calculate samples per class
    classes = temp["Target"].unique()

    samples_per_class = (
        MAX_TRAINING_ROWS // len(classes)
    )


    sampled_parts = []


    for class_value in classes:

        class_data = temp[
            temp["Target"] == class_value
        ]

        number_to_take = min(
            samples_per_class,
            len(class_data)
        )

        sampled = class_data.sample(
            n=number_to_take,
            random_state=42
        )

        sampled_parts.append(
            sampled
        )


    temp = pd.concat(
        sampled_parts,
        ignore_index=True
    )


    # Shuffle
    temp = temp.sample(
        frac=1,
        random_state=42
    ).reset_index(
        drop=True
    )


    X = temp[
        FEATURES
    ].copy()

    y = temp[
        "Target"
    ].copy()


    del temp


    print(
        "Sampled rows:",
        len(X)
    )


else:

    print(
        "\nDataset size is suitable for training."
    )


# ============================================================
# FINAL CLASS DISTRIBUTION
# ============================================================

print("\nFINAL TRAINING DATA:")

print(
    "Rows:",
    len(X)
)

print(
    "Features:",
    X.shape[1]
)

print(
    "\nClasses:"
)

print(
    y.value_counts()
)


# ============================================================
# TRAIN / TEST SPLIT
# ============================================================

print("\n" + "=" * 70)
print("CREATING TRAIN / TEST DATA")
print("=" * 70)


X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


print(
    "Training samples:",
    len(X_train)
)

print(
    "Testing samples:",
    len(X_test)
)


# ============================================================
# SCALER
# ============================================================

print("\nCreating StandardScaler...")


scaler = StandardScaler()


X_train_scaled = scaler.fit_transform(
    X_train
)

X_test_scaled = scaler.transform(
    X_test
)


# ============================================================
# RANDOM FOREST
# ============================================================

print("\n" + "=" * 70)
print("TRAINING RANDOM FOREST")
print("=" * 70)

print(
    "Trees: 100"
)

print(
    "Maximum depth: 20"
)

print(
    "CPU threads: 2"
)


model = RandomForestClassifier(

    n_estimators=100,

    max_depth=20,

    min_samples_leaf=2,

    random_state=42,

    n_jobs=2,

    class_weight="balanced",

    max_features="sqrt"

)


model.fit(
    X_train_scaled,
    y_train
)


print(
    "\nRandom Forest training completed!"
)


# ============================================================
# TEST MODEL
# ============================================================

print("\n" + "=" * 70)
print("MODEL EVALUATION")
print("=" * 70)


y_pred = model.predict(
    X_test_scaled
)


accuracy = accuracy_score(
    y_test,
    y_pred
)

precision = precision_score(
    y_test,
    y_pred,
    zero_division=0
)

recall = recall_score(
    y_test,
    y_pred,
    zero_division=0
)

f1 = f1_score(
    y_test,
    y_pred,
    zero_division=0
)

# ROC-AUC requires probability scores for the positive class (DDoS).
y_proba = model.predict_proba(X_test_scaled)[:, 1]
roc_auc = roc_auc_score(
    y_test,
    y_proba
)

# Confusion matrix order:
# [[TN, FP],
#  [FN, TP]]
cm = confusion_matrix(
    y_test,
    y_pred,
    labels=[0, 1]
)

true_negative = int(cm[0, 0])
false_positive = int(cm[0, 1])
false_negative = int(cm[1, 0])
true_positive = int(cm[1, 1])

print(
    "\nAccuracy:",
    f"{accuracy * 100:.2f}%"
)

print(
    "Precision:",
    f"{precision * 100:.2f}%"
)

print(
    "Recall:",
    f"{recall * 100:.2f}%"
)

print(
    "F1 Score:",
    f"{f1 * 100:.2f}%"
)

print(
    "ROC-AUC:",
    f"{roc_auc * 100:.2f}%"
)

print("\nConfusion Matrix:")
print(cm)

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        y_pred,
        target_names=[
            "BENIGN",
            "DDoS"
        ]
    )
)

# ------------------------------------------------------------
# SAVE VALIDATION METRICS FOR THE AI-NET DASHBOARD
# ------------------------------------------------------------

metrics_path = os.path.join(
    "models",
    "model_metrics.json"
)

metrics_data = {
    "accuracy": float(accuracy),
    "precision": float(precision),
    "recall": float(recall),
    "f1_score": float(f1),
    "roc_auc": float(roc_auc),
    "true_negative": true_negative,
    "false_positive": false_positive,
    "false_negative": false_negative,
    "true_positive": true_positive,
    "confusion_matrix": cm.tolist(),
    "test_samples": int(len(y_test)),
    "training_samples": int(len(y_train)),
    "feature_count": int(len(FEATURES)),
    "model_type": type(model).__name__,
    "classes": {
        "0": "BENIGN",
        "1": "DDoS"
    }
}

with open(
    metrics_path,
    "w",
    encoding="utf-8"
) as metrics_file:

    json.dump(
        metrics_data,
        metrics_file,
        indent=4
    )

print(
    "\nValidation metrics saved:",
    metrics_path
)


# ============================================================
# SAVE MODELS
# ============================================================

print("\n" + "=" * 70)
print("SAVING MODEL")
print("=" * 70)


os.makedirs(
    "models",
    exist_ok=True
)


model_path = (
    "models/random_forest_model.pkl"
)

scaler_path = (
    "models/scaler.pkl"
)

features_path = (
    "model_features.txt"
)


joblib.dump(
    model,
    model_path
)


joblib.dump(
    scaler,
    scaler_path
)


# ============================================================
# SAVE EXACT FEATURE ORDER
# ============================================================

with open(
    features_path,
    "w",
    encoding="utf-8"
) as file:

    for i, feature in enumerate(
        FEATURES,
        1
    ):

        file.write(
            f"{i}. {feature}\n"
        )


print(
    "\nModel saved:",
    model_path
)

print(
    "Scaler saved:",
    scaler_path
)

print(
    "Feature list saved:",
    features_path
)

print(
    "Metrics saved:",
    metrics_path
)


# ============================================================
# VERIFY SAVED FILES
# ============================================================

print("\n" + "=" * 70)
print("VERIFYING MODEL")
print("=" * 70)


loaded_model = joblib.load(
    model_path
)

loaded_scaler = joblib.load(
    scaler_path
)


print(
    "Model feature count:",
    loaded_model.n_features_in_
)

print(
    "Scaler feature count:",
    loaded_scaler.n_features_in_
)


if loaded_model.n_features_in_ != 10:

    print(
        "\nERROR: Model does not contain exactly 10 features."
    )

    raise SystemExit(1)


if loaded_scaler.n_features_in_ != 10:

    print(
        "\nERROR: Scaler does not contain exactly 10 features."
    )

    raise SystemExit(1)


# ============================================================
# TEST SAMPLE
# ============================================================

print("\n" + "=" * 70)
print("TESTING SAMPLE PREDICTION")
print("=" * 70)


sample = X_test.iloc[
    [0]
]


sample_scaled = loaded_scaler.transform(
    sample
)


prediction = loaded_model.predict(
    sample_scaled
)[0]


probabilities = loaded_model.predict_proba(
    sample_scaled
)[0]


if prediction == 0:

    prediction_name = "BENIGN"

else:

    prediction_name = "DDoS"


print(
    "\nPrediction:",
    prediction_name
)


print(
    f"BENIGN probability: "
    f"{probabilities[0] * 100:.2f}%"
)


print(
    f"DDoS probability: "
    f"{probabilities[1] * 100:.2f}%"
)


# ============================================================
# FINAL SUCCESS
# ============================================================

print("\n" + "=" * 70)
print("AI-NET MODEL TRAINING COMPLETE")
print("=" * 70)

print(
    "\nSUCCESS!"
)

print(
    "Model and scaler both use exactly 10 features."
)

print(
    "The model is ready for the Flask application."
)

print("=" * 70)