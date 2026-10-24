"""
train_model.py
Trains phishing detection models on a labelled dataset and saves the best model.

Supported dataset formats:
  1. Pre-extracted features CSV with numeric columns + a binary target column.
  2. Raw URL CSV with a 'url' column + a binary target column.

Usage:
    python train_model.py --dataset data/phishing_dataset.csv --target Result
    python train_model.py --dataset data/phishing_dataset.csv --target label --url-column url
"""

import argparse
import json
import os
import sys
import warnings
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")  # non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from feature_extraction import FEATURE_NAMES, extract_features

warnings.filterwarnings("ignore")

MODEL_DIR = Path("models")
DATA_DIR = Path("data")
MODEL_PATH = MODEL_DIR / "phishguard_model.joblib"
METADATA_PATH = MODEL_DIR / "model_metadata.json"
PLOTS_DIR = MODEL_DIR / "plots"

# Map target column values to 0 (legitimate) and 1 (phishing)
# UCI Phishing dataset: 1=phishing, -1=legitimate
# Standard binary: 1=phishing, 0=legitimate
PHISHING_LABELS = {"1", "phishing", "phish", "bad", "1.0"}
LEGIT_LABELS = {"0", "-1", "legitimate", "legit", "good", "0.0", "-1.0"}


def normalise_labels(series: pd.Series) -> pd.Series:
    """Convert varied label formats to 0/1 integers."""
    def map_label(val):
        if str(val).lower() in {str(v).lower() for v in PHISHING_LABELS}:
            return 1
        if str(val).lower() in {str(v).lower() for v in LEGIT_LABELS}:
            return 0
        # Try numeric (UCI: 1=phishing, -1=legitimate; Standard: 1=phishing, 0=legitimate)
        try:
            n = float(val)
            if n == 1.0:
                return 1
            if n == 0.0 or n == -1.0:
                return 0
        except (ValueError, TypeError):
            pass
        return None

    mapped = series.map(map_label)
    if mapped.isnull().any():
        bad_vals = series[mapped.isnull()].unique()[:5]
        raise ValueError(
            f"Unrecognised target values: {bad_vals}. "
            "Expected 0/1, 'legitimate'/'phishing', or -1/1."
        )
    return mapped.astype(int)


def load_dataset(path: str, target_col: str, url_col: str = None):
    """
    Load and prepare dataset.

    Parameters
    ----------
    path : str
        Path to CSV file.
    target_col : str
        Name of the target/label column.
    url_col : str or None
        If provided, extract features from this URL column.

    Returns
    -------
    X : pd.DataFrame
    y : pd.Series
    feature_names : list[str]
    """
    print(f"[INFO] Loading dataset from: {path}")
    df = pd.read_csv(path, low_memory=False)
    print(f"[INFO] Shape: {df.shape}")
    print(f"[INFO] Columns: {list(df.columns)}")

    if target_col not in df.columns:
        raise ValueError(
            f"Target column '{target_col}' not found. "
            f"Available columns: {list(df.columns)}"
        )

    # Drop rows where target is missing
    df = df.dropna(subset=[target_col])
    y = normalise_labels(df[target_col])

    print(f"[INFO] Class distribution:\n{y.value_counts().to_string()}")

    if url_col is not None:
        # Extract features from URLs
        if url_col not in df.columns:
            raise ValueError(f"URL column '{url_col}' not found.")
        print(f"[INFO] Extracting features from URL column: '{url_col}'")
        feature_rows = []
        bad = 0
        for i, raw_url in enumerate(df[url_col]):
            try:
                feats = extract_features(str(raw_url))
                feature_rows.append(feats)
            except Exception:
                feature_rows.append({fn: 0 for fn in FEATURE_NAMES})
                bad += 1
            if (i + 1) % 5000 == 0:
                print(f"  Processed {i+1}/{len(df)} URLs...")
        if bad > 0:
            print(f"[WARN] {bad} URLs could not be parsed; zeros used for their features.")
        X = pd.DataFrame(feature_rows, index=df.index)[FEATURE_NAMES]
        feature_names = FEATURE_NAMES
    else:
        # Use pre-extracted numeric features
        drop_cols = [target_col]
        # Also drop obvious non-feature columns
        for col in ["url", "URL", "domain", "index", "id", "Index"]:
            if col in df.columns:
                drop_cols.append(col)
        X = df.drop(columns=drop_cols, errors="ignore")

        # Keep only numeric columns
        X = X.select_dtypes(include=[np.number])
        if X.empty:
            raise ValueError("No numeric feature columns found after dropping target and URL columns.")
        feature_names = list(X.columns)
        print(f"[INFO] Using {len(feature_names)} pre-extracted numeric features.")

    print(f"[INFO] Feature matrix shape: {X.shape}")
    return X, y, feature_names


def build_pipeline(model):
    """Wrap a model in a preprocessing pipeline."""
    return Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler()),
        ("classifier", model),
    ])


def evaluate_model(pipeline, X_test, y_test, model_name: str) -> dict:
    """Evaluate a fitted pipeline and return metrics dict."""
    y_pred = pipeline.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred).tolist()

    roc_auc = None
    if hasattr(pipeline, "predict_proba"):
        try:
            y_prob = pipeline.predict_proba(X_test)[:, 1]
            roc_auc = round(float(roc_auc_score(y_test, y_prob)), 4)
        except Exception:
            pass

    report = classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"], output_dict=True)

    return {
        "model_name": model_name,
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1_score": round(float(f1), 4),
        "roc_auc": roc_auc,
        "confusion_matrix": cm,
        "classification_report": report,
    }


def save_plots(results: list, confusion_mat: list, model_name: str):
    """Save evaluation plots to disk."""
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Model comparison bar chart
    fig, ax = plt.subplots(figsize=(10, 6))
    metrics = ["accuracy", "precision", "recall", "f1_score"]
    x = np.arange(len(results))
    width = 0.18
    colors = ["#4e9af1", "#63e6be", "#f8a84b", "#ff6b6b"]
    for i, metric in enumerate(metrics):
        vals = [r[metric] for r in results]
        bars = ax.bar(x + i * width, vals, width, label=metric.replace("_", " ").title(), color=colors[i], alpha=0.85)
        for bar in bars:
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.005,
                    f"{bar.get_height():.3f}", ha="center", va="bottom", fontsize=8)
    ax.set_xticks(x + width * 1.5)
    ax.set_xticklabels([r["model_name"] for r in results])
    ax.set_ylim(0, 1.12)
    ax.set_ylabel("Score")
    ax.set_title("Model Comparison — Phishing Detection")
    ax.legend(loc="lower right")
    ax.set_facecolor("#0d1b2a")
    fig.patch.set_facecolor("#0d1b2a")
    ax.tick_params(colors="white")
    ax.yaxis.label.set_color("white")
    ax.xaxis.label.set_color("white")
    ax.title.set_color("white")
    for spine in ax.spines.values():
        spine.set_edgecolor("#2a3f5f")
    ax.legend(facecolor="#1a2744", labelcolor="white")
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / "model_comparison.png", dpi=120, bbox_inches="tight")
    plt.close()

    # 2. Confusion matrix heatmap
    cm_arr = np.array(confusion_mat)
    fig, ax = plt.subplots(figsize=(6, 5))
    sns.heatmap(
        cm_arr, annot=True, fmt="d", cmap="Blues",
        xticklabels=["Legitimate", "Phishing"],
        yticklabels=["Legitimate", "Phishing"],
        ax=ax, cbar=True, linewidths=0.5
    )
    ax.set_xlabel("Predicted", color="white")
    ax.set_ylabel("Actual", color="white")
    ax.set_title(f"Confusion Matrix — {model_name}", color="white")
    ax.set_facecolor("#0d1b2a")
    fig.patch.set_facecolor("#0d1b2a")
    ax.tick_params(colors="white")
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / "confusion_matrix.png", dpi=120, bbox_inches="tight")
    plt.close()

    print(f"[INFO] Plots saved to {PLOTS_DIR}/")


def train(dataset_path: str, target_col: str, url_col: str = None,
          test_size: float = 0.2, random_state: int = 42):
    """
    Full training pipeline.
    Returns metadata dict with all results.
    """
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Load data
    X, y, feature_names = load_dataset(dataset_path, target_col, url_col)

    n_samples = len(X)
    n_train = int(n_samples * (1 - test_size))
    n_test = n_samples - n_train
    n_phishing = int(y.sum())
    n_legit = n_samples - n_phishing

    print(f"\n[INFO] Dataset: {n_samples} samples | Phishing: {n_phishing} | Legitimate: {n_legit}")

    # 2. Stratified split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )
    print(f"[INFO] Train: {len(X_train)} | Test: {len(X_test)}")

    # 3. Define models
    models = {
        "Logistic Regression": LogisticRegression(
            max_iter=1000, random_state=random_state, class_weight="balanced"
        ),
        "Decision Tree": DecisionTreeClassifier(
            max_depth=15, min_samples_split=10,
            random_state=random_state, class_weight="balanced"
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators=100, max_depth=20, min_samples_split=5,
            random_state=random_state, class_weight="balanced",
            n_jobs=-1
        ),
    }

    # 4. Train and evaluate each model
    all_results = []
    fitted_pipelines = {}

    for name, model in models.items():
        print(f"\n[INFO] Training {name}...")
        pipeline = build_pipeline(model)
        pipeline.fit(X_train, y_train)
        result = evaluate_model(pipeline, X_test, y_test, name)
        all_results.append(result)
        fitted_pipelines[name] = pipeline

        print(f"  Accuracy : {result['accuracy']:.4f}")
        print(f"  Precision: {result['precision']:.4f}")
        print(f"  Recall   : {result['recall']:.4f}")
        print(f"  F1-Score : {result['f1_score']:.4f}")
        if result["roc_auc"]:
            print(f"  ROC-AUC  : {result['roc_auc']:.4f}")

    # 5. Select best model (prioritise F1, then recall)
    best = max(all_results, key=lambda r: (r["f1_score"], r["recall"]))
    best_name = best["model_name"]
    best_pipeline = fitted_pipelines[best_name]

    print(f"\n[INFO] Best model: {best_name} (F1={best['f1_score']:.4f}, Recall={best['recall']:.4f})")

    # 6. Save model
    joblib.dump(best_pipeline, MODEL_PATH)
    print(f"[INFO] Model saved -> {MODEL_PATH}")

    # 7. Save plots
    try:
        save_plots(all_results, best["confusion_matrix"], best_name)
    except Exception as e:
        print(f"[WARN] Could not save plots: {e}")

    # 8. Save metadata
    metadata = {
        "dataset_name": os.path.basename(dataset_path),
        "dataset_path": dataset_path,
        "selected_model": best_name,
        "feature_names": feature_names,
        "url_column": url_col,
        "target_column": target_col,
        "training_date": datetime.now().isoformat(),
        "n_samples": n_samples,
        "n_train": n_train,
        "n_test": n_test,
        "n_phishing": n_phishing,
        "n_legitimate": n_legit,
        "test_size": test_size,
        "random_state": random_state,
        "best_metrics": best,
        "all_model_results": all_results,
    }

    with open(METADATA_PATH, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"[INFO] Metadata saved -> {METADATA_PATH}")

    return metadata


def main():
    parser = argparse.ArgumentParser(description="PhishGuard Model Trainer")
    parser.add_argument("--dataset", required=True, help="Path to the CSV dataset file.")
    parser.add_argument("--target", required=True, help="Name of the target/label column.")
    parser.add_argument("--url-column", default=None,
                        help="Name of the URL column (if features need to be extracted from raw URLs).")
    parser.add_argument("--test-size", type=float, default=0.2,
                        help="Fraction of data for testing (default: 0.2).")
    parser.add_argument("--random-state", type=int, default=42,
                        help="Random seed (default: 42).")
    args = parser.parse_args()

    if not os.path.isfile(args.dataset):
        print(f"[ERROR] Dataset not found: {args.dataset}")
        sys.exit(1)

    try:
        metadata = train(
            dataset_path=args.dataset,
            target_col=args.target,
            url_col=args.url_column,
            test_size=args.test_size,
            random_state=args.random_state,
        )
        print("\n[SUCCESS] Training complete.")
        print(f"  Selected model : {metadata['selected_model']}")
        print(f"  Accuracy       : {metadata['best_metrics']['accuracy']:.4f}")
        print(f"  F1-Score       : {metadata['best_metrics']['f1_score']:.4f}")
        print(f"  Recall         : {metadata['best_metrics']['recall']:.4f}")
    except Exception as e:
        print(f"[ERROR] Training failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
