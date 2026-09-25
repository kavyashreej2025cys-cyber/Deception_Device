"""
Train and evaluate the cyber-deception Random Forest classifier.

Run from the project virtual environment:

    cd ~/cyber-deception
    venv/bin/python ai/train.py
"""

import csv
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import joblib
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import StratifiedKFold, cross_validate, cross_val_predict


BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "dataset" / "training_data.csv"
MODEL_DIR = BASE_DIR / "models"
REPORT_DIR = BASE_DIR / "reports"

MODEL_PATH = MODEL_DIR / "random_forest.joblib"
REPORT_PATH = REPORT_DIR / "evaluation.json"
IMPORTANCE_PATH = REPORT_DIR / "feature_importance.csv"

FEATURE_COLUMNS = [
    "event_count",
    "unique_services",
    "ssh_events",
    "web_events",
    "database_events",
    "iot_events",
    "login_attempts",
    "query_attempts",
    "camera_attempts",
    "session_duration",
]

LABEL_COLUMN = "label"

RANDOM_STATE = 42
CROSS_VALIDATION_FOLDS = 3


def calculate_sha256(file_path):
    """Return the SHA-256 digest of a file."""
    digest = hashlib.sha256()

    with file_path.open("rb") as source_file:
        for chunk in iter(lambda: source_file.read(65536), b""):
            digest.update(chunk)

    return digest.hexdigest()


def load_dataset():
    """Load and validate the training CSV."""
    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Training dataset was not found: {DATASET_PATH}"
        )

    with DATASET_PATH.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as csv_file:
        reader = csv.DictReader(csv_file)

        if reader.fieldnames is None:
            raise ValueError("The dataset does not contain a header row.")

        required_columns = set(FEATURE_COLUMNS + [LABEL_COLUMN])
        actual_columns = set(reader.fieldnames)
        missing_columns = sorted(required_columns - actual_columns)

        if missing_columns:
            raise ValueError(
                "Dataset is missing required columns: "
                + ", ".join(missing_columns)
            )

        feature_rows = []
        labels = []

        for line_number, row in enumerate(reader, start=2):
            label = (row.get(LABEL_COLUMN) or "").strip()

            if not label:
                raise ValueError(
                    f"Missing label at CSV line {line_number}."
                )

            numeric_row = []

            for feature_name in FEATURE_COLUMNS:
                raw_value = (row.get(feature_name) or "").strip()

                if raw_value == "":
                    raise ValueError(
                        f"Missing value for {feature_name} "
                        f"at CSV line {line_number}."
                    )

                try:
                    numeric_value = float(raw_value)
                except ValueError as error:
                    raise ValueError(
                        f"Invalid numeric value for {feature_name} "
                        f"at CSV line {line_number}: {raw_value!r}"
                    ) from error

                if numeric_value < 0:
                    raise ValueError(
                        f"Negative value for {feature_name} "
                        f"at CSV line {line_number}."
                    )

                numeric_row.append(numeric_value)

            feature_rows.append(numeric_row)
            labels.append(label)

    if not feature_rows:
        raise ValueError("The training dataset contains no data rows.")

    return feature_rows, labels


def validate_class_counts(labels):
    """Ensure every class supports stratified cross-validation."""
    class_counts = Counter(labels)
    smallest_class_size = min(class_counts.values())

    if smallest_class_size < CROSS_VALIDATION_FOLDS:
        raise ValueError(
            "The smallest class has only "
            f"{smallest_class_size} rows, but "
            f"{CROSS_VALIDATION_FOLDS}-fold stratified "
            "cross-validation requires at least "
            f"{CROSS_VALIDATION_FOLDS} rows per class."
        )

    return class_counts


def create_model():
    """Create a reproducible Random Forest classifier."""
    return RandomForestClassifier(
        n_estimators=300,
        criterion="gini",
        max_depth=None,
        min_samples_split=2,
        min_samples_leaf=1,
        max_features="sqrt",
        class_weight="balanced",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )


def evaluate_model(features, labels, class_names):
    """Evaluate the model using stratified cross-validation."""
    cross_validator = StratifiedKFold(
        n_splits=CROSS_VALIDATION_FOLDS,
        shuffle=True,
        random_state=RANDOM_STATE,
    )

    scoring = {
        "accuracy": "accuracy",
        "precision_macro": "precision_macro",
        "recall_macro": "recall_macro",
        "f1_macro": "f1_macro",
    }

    scores = cross_validate(
        estimator=create_model(),
        X=features,
        y=labels,
        cv=cross_validator,
        scoring=scoring,
        n_jobs=-1,
        return_train_score=False,
    )

    predicted_labels = cross_val_predict(
        estimator=create_model(),
        X=features,
        y=labels,
        cv=cross_validator,
        n_jobs=-1,
        method="predict",
    )

    metrics_summary = {}

    for metric_name in scoring:
        values = scores[f"test_{metric_name}"]

        metrics_summary[metric_name] = {
            "fold_values": [round(float(value), 4) for value in values],
            "mean": round(float(values.mean()), 4),
            "standard_deviation": round(float(values.std()), 4),
        }

    report = classification_report(
        labels,
        predicted_labels,
        labels=class_names,
        output_dict=True,
        zero_division=0,
    )

    matrix = confusion_matrix(
        labels,
        predicted_labels,
        labels=class_names,
    )

    return {
        "cross_validation": metrics_summary,
        "classification_report": report,
        "confusion_matrix": {
            "labels": class_names,
            "matrix": matrix.tolist(),
        },
    }


def save_feature_importance(model):
    """Write sorted feature-importance values to CSV."""
    ranked_features = sorted(
        zip(FEATURE_COLUMNS, model.feature_importances_),
        key=lambda item: item[1],
        reverse=True,
    )

    with IMPORTANCE_PATH.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["feature", "importance"])

        for feature_name, importance in ranked_features:
            writer.writerow(
                [
                    feature_name,
                    f"{float(importance):.8f}",
                ]
            )

    return ranked_features


def print_results(
    class_counts,
    evaluation,
    ranked_features,
    model_path,
):
    """Print a readable training summary."""
    print("\nClass distribution:")

    for label, count in sorted(class_counts.items()):
        print(f"  {label}: {count}")

    print(
        f"\n{CROSS_VALIDATION_FOLDS}-fold "
        "stratified cross-validation:"
    )

    for metric_name, values in evaluation[
        "cross_validation"
    ].items():
        print(
            f"  {metric_name}: "
            f"{values['mean']:.4f} "
            f"(+/- {values['standard_deviation']:.4f})"
        )
        print(f"    folds: {values['fold_values']}")

    confusion = evaluation["confusion_matrix"]

    print("\nConfusion matrix:")
    print("  Label order:")

    for index, label in enumerate(confusion["labels"]):
        print(f"    {index}: {label}")

    for row in confusion["matrix"]:
        print("   ", row)

    print("\nFeature importance:")

    for feature_name, importance in ranked_features:
        print(f"  {feature_name}: {importance:.4f}")

    print(f"\nFinal model saved to: {model_path}")
    print(f"Evaluation saved to: {REPORT_PATH}")
    print(f"Feature importance saved to: {IMPORTANCE_PATH}")


def main():
    """Load data, evaluate, train, and save the final model."""
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    features, labels = load_dataset()
    class_counts = validate_class_counts(labels)
    class_names = sorted(class_counts)

    print(f"Dataset: {DATASET_PATH}")
    print(f"Rows: {len(features)}")
    print(f"Features: {len(FEATURE_COLUMNS)}")
    print(f"Classes: {len(class_names)}")
    print(f"Dataset SHA-256: {calculate_sha256(DATASET_PATH)}")

    evaluation = evaluate_model(
        features=features,
        labels=labels,
        class_names=class_names,
    )

    final_model = create_model()
    final_model.fit(features, labels)

    ranked_features = save_feature_importance(final_model)

    trained_at = datetime.now(timezone.utc).isoformat()
    dataset_hash = calculate_sha256(DATASET_PATH)

    model_bundle = {
        "model": final_model,
        "feature_columns": FEATURE_COLUMNS,
        "class_names": class_names,
        "metadata": {
            "model_type": "RandomForestClassifier",
            "trained_at_utc": trained_at,
            "training_rows": len(features),
            "dataset_path": str(DATASET_PATH),
            "dataset_sha256": dataset_hash,
            "random_state": RANDOM_STATE,
            "cross_validation_folds": CROSS_VALIDATION_FOLDS,
            "scikit_learn_version": sklearn.__version__,
        },
    }

    joblib.dump(model_bundle, MODEL_PATH)

    evaluation_document = {
        "generated_at_utc": trained_at,
        "dataset": {
            "path": str(DATASET_PATH),
            "sha256": dataset_hash,
            "row_count": len(features),
            "feature_count": len(FEATURE_COLUMNS),
            "class_counts": dict(sorted(class_counts.items())),
        },
        "model": model_bundle["metadata"],
        "evaluation": evaluation,
    }

    with REPORT_PATH.open("w", encoding="utf-8") as report_file:
        json.dump(
            evaluation_document,
            report_file,
            indent=2,
            sort_keys=True,
        )

    print_results(
        class_counts=class_counts,
        evaluation=evaluation,
        ranked_features=ranked_features,
        model_path=MODEL_PATH,
    )

    print(
        "\nImportant: these are preliminary metrics from only "
        f"{len(features)} synthetic scenarios. Do not treat them "
        "as production performance estimates."
    )


if __name__ == "__main__":
    main()
