"""
app.py  —  PhishGuard Flask Backend
Provides REST API endpoints for phishing URL detection.
"""

import json
import logging
import os
import re
import sqlite3
import threading
import time
import traceback
import urllib.parse
from datetime import datetime
from functools import wraps
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from flask import Flask, jsonify, request, send_from_directory, render_template
from flask_cors import CORS

from feature_extraction import (
    FEATURE_NAMES,
    extract_features,
    features_to_list,
    get_feature_explanations,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).parent
MODEL_DIR = BASE_DIR / "models"
MODEL_PATH = MODEL_DIR / "phishguard_model.joblib"
METADATA_PATH = MODEL_DIR / "model_metadata.json"

# On Vercel, serverless environment filesystem is read-only except /tmp
if os.environ.get("VERCEL"):
    DB_DIR = Path("/tmp")
    DB_PATH = DB_DIR / "phishguard.db"
else:
    DB_DIR = BASE_DIR / "database"
    DB_PATH = DB_DIR / "phishguard.db"
    DB_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("PhishGuard")

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
)
CORS(app, origins="*")

# ---------------------------------------------------------------------------
# Global model state
# ---------------------------------------------------------------------------
_model = None
_metadata = None
_model_lock = threading.Lock()
_training_lock = threading.Lock()
_is_training = False


def load_model():
    """Load model and metadata from disk. Thread-safe."""
    global _model, _metadata
    with _model_lock:
        if MODEL_PATH.exists():
            try:
                _model = joblib.load(MODEL_PATH)
                logger.info("Model loaded from %s", MODEL_PATH)
            except Exception as e:
                logger.error("Failed to load model: %s", e)
                _model = None
        else:
            _model = None
            logger.warning("No trained model found at %s", MODEL_PATH)

        if METADATA_PATH.exists():
            try:
                with open(METADATA_PATH) as f:
                    _metadata = json.load(f)
                logger.info("Metadata loaded: %s", _metadata.get("selected_model", "?"))
            except Exception as e:
                logger.error("Failed to load metadata: %s", e)
                _metadata = None
        else:
            _metadata = None


def model_ready():
    return _model is not None and _metadata is not None


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
def init_db():
    conn = sqlite3.connect(str(DB_PATH))
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            display_url TEXT NOT NULL,
            prediction TEXT NOT NULL,
            confidence REAL NOT NULL,
            is_phishing INTEGER NOT NULL,
            features TEXT,
            scanned_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()
    logger.info("Database initialised at %s", DB_PATH)


def save_scan(url: str, display_url: str, prediction: str,
              confidence: float, is_phishing: bool, features: dict):
    """Persist a scan result to the database."""
    conn = sqlite3.connect(str(DB_PATH))
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO scan_history
            (url, display_url, prediction, confidence, is_phishing, features, scanned_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        url,
        display_url,
        prediction,
        round(confidence, 4),
        int(is_phishing),
        json.dumps({k: float(v) if isinstance(v, (np.floating, float)) else v
                    for k, v in features.items()}),
        datetime.now().isoformat(),
    ))
    conn.commit()
    conn.close()


def get_history(limit: int = 100):
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("""
        SELECT id, display_url, prediction, confidence, is_phishing, scanned_at
        FROM scan_history
        ORDER BY scanned_at DESC
        LIMIT ?
    """, (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def clear_history_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("DELETE FROM scan_history")
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Input helpers
# ---------------------------------------------------------------------------
MAX_URL_LEN = 2048

REDACT_PARAMS = {"password", "passwd", "pwd", "token", "secret",
                 "api_key", "apikey", "auth", "access_token"}


def make_display_url(url: str) -> str:
    """Return URL with sensitive query params redacted."""
    try:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        redacted = {
            k: (["[REDACTED]"] if k.lower() in REDACT_PARAMS else v)
            for k, v in params.items()
        }
        new_query = urllib.parse.urlencode(redacted, doseq=True)
        display = parsed._replace(query=new_query).geturl()
        return display
    except Exception:
        return url[:200]


def validate_url(url: str):
    """
    Basic URL validation. Returns (clean_url, error_message).
    Raises nothing — error_message is None on success.
    """
    if not url or not isinstance(url, str):
        return None, "URL must be a non-empty string."
    url = url.strip()
    if len(url) > MAX_URL_LEN:
        return None, f"URL too long (max {MAX_URL_LEN} characters)."
    if "\n" in url or "\r" in url or "\x00" in url:
        return None, "URL contains illegal characters."
    # Add scheme if missing (needed for parsing, but keep original for display)
    parsed_url = url
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", url):
        parsed_url = "http://" + url
    return parsed_url, None


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------
def json_error(message: str, status: int = 400) -> tuple:
    return jsonify({"error": message, "status": status}), status


def require_json(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not request.is_json:
            return json_error("Request must be JSON (Content-Type: application/json)", 415)
        return f(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# Routes — Pages
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scanner")
def scanner():
    return render_template("scanner.html")


@app.route("/performance")
def performance():
    return render_template("performance.html")


@app.route("/history")
def history_page():
    return render_template("history.html")


@app.route("/about")
def about():
    return render_template("about.html")


# ---------------------------------------------------------------------------
# API — Health
# ---------------------------------------------------------------------------
@app.route("/api/health")
def api_health():
    return jsonify({
        "status": "ok",
        "model_ready": model_ready(),
        "model_name": _metadata.get("selected_model") if _metadata else None,
        "trained_on": _metadata.get("training_date") if _metadata else None,
        "timestamp": datetime.now().isoformat(),
    })


# ---------------------------------------------------------------------------
# API — Predict
# ---------------------------------------------------------------------------
@app.route("/api/predict", methods=["POST"])
@require_json
def api_predict():
    data = request.get_json(silent=True) or {}
    raw_url = data.get("url", "")

    url, err = validate_url(raw_url)
    if err:
        return json_error(err, 400)

    display_url = make_display_url(url)

    # Feature extraction
    try:
        features = extract_features(url)
    except ValueError as e:
        return json_error(f"URL parsing error: {e}", 422)
    except Exception:
        logger.error("Feature extraction failed:\n%s", traceback.format_exc())
        return json_error("Internal error during feature extraction.", 500)

    # Model prediction
    if not model_ready():
        return jsonify({
            "status": "no_model",
            "message": (
                "No trained model is available. "
                "Please train the model first using the /api/train endpoint "
                "or by running: python train_model.py --dataset data/phishing_dataset.csv --target <label_column>"
            ),
            "display_url": display_url,
            "features": features,
        }), 503

    feature_names = _metadata.get("feature_names", FEATURE_NAMES)
    feature_vector = features_to_list(features, feature_names)

    try:
        X = pd.DataFrame([feature_vector], columns=feature_names)
        prediction_int = int(_model.predict(X)[0])
        is_phishing = prediction_int == 1

        # Confidence score
        if hasattr(_model, "predict_proba"):
            proba = _model.predict_proba(X)[0]
            confidence = float(proba[prediction_int])
        else:
            confidence = 0.75  # fallback for models without predict_proba

        prediction_label = "Phishing" if is_phishing else "Legitimate"

    except Exception:
        logger.error("Prediction failed:\n%s", traceback.format_exc())
        return json_error("Model prediction failed.", 500)

    # Explanations
    explanations = get_feature_explanations(features)

    # Persist to DB
    try:
        save_scan(url, display_url, prediction_label, confidence, is_phishing, features)
    except Exception as e:
        logger.warning("Could not save scan to DB: %s", e)

    # Build response
    response = {
        "status": "ok",
        "display_url": display_url,
        "prediction": prediction_label,
        "is_phishing": is_phishing,
        "confidence": round(confidence * 100, 1),
        "features": {k: (float(v) if isinstance(v, (np.floating, float)) else v)
                     for k, v in features.items()},
        "explanations": explanations,
        "model_used": _metadata.get("selected_model", "Unknown"),
        "disclaimer": (
            "This result is a machine learning prediction, not a guarantee of website safety. "
            "URL-based models may miss sophisticated phishing sites and may occasionally "
            "flag legitimate sites."
        ),
    }
    return jsonify(response)


# ---------------------------------------------------------------------------
# API — Metrics
# ---------------------------------------------------------------------------
@app.route("/api/metrics")
def api_metrics():
    if not _metadata:
        return jsonify({
            "status": "no_model",
            "message": "No model metadata available. Train the model first.",
        }), 503

    return jsonify({
        "status": "ok",
        "dataset_name": _metadata.get("dataset_name"),
        "selected_model": _metadata.get("selected_model"),
        "training_date": _metadata.get("training_date"),
        "n_samples": _metadata.get("n_samples"),
        "n_train": _metadata.get("n_train"),
        "n_test": _metadata.get("n_test"),
        "n_phishing": _metadata.get("n_phishing"),
        "n_legitimate": _metadata.get("n_legitimate"),
        "feature_names": _metadata.get("feature_names", FEATURE_NAMES),
        "best_metrics": _metadata.get("best_metrics"),
        "all_model_results": _metadata.get("all_model_results", []),
    })


# ---------------------------------------------------------------------------
# API — History
# ---------------------------------------------------------------------------
@app.route("/api/history", methods=["GET"])
def api_history():
    try:
        limit = min(int(request.args.get("limit", 100)), 500)
        rows = get_history(limit)
        return jsonify({"status": "ok", "history": rows, "count": len(rows)})
    except Exception:
        logger.error("History retrieval failed:\n%s", traceback.format_exc())
        return json_error("Failed to retrieve history.", 500)


@app.route("/api/history", methods=["DELETE"])
def api_history_delete():
    try:
        clear_history_db()
        return jsonify({"status": "ok", "message": "Scan history cleared."})
    except Exception:
        logger.error("History deletion failed:\n%s", traceback.format_exc())
        return json_error("Failed to clear history.", 500)


# ---------------------------------------------------------------------------
# API — Train
# ---------------------------------------------------------------------------
@app.route("/api/train", methods=["POST"])
@require_json
def api_train():
    global _is_training

    if _is_training:
        return json_error("Training is already in progress. Please wait.", 409)

    data = request.get_json(silent=True) or {}
    dataset = data.get("dataset", "data/phishing_dataset.csv")
    target_col = data.get("target_column", "Result")
    url_col = data.get("url_column", None)

    # Security: only allow paths within data/ directory
    safe_base = (BASE_DIR / "data").resolve()
    dataset_path = (BASE_DIR / dataset).resolve()
    try:
        dataset_path.relative_to(safe_base)
    except ValueError:
        return json_error("Dataset must be located within the data/ directory.", 403)

    if not dataset_path.exists():
        return json_error(
            f"Dataset not found: {dataset}. "
            "Place your CSV file in the data/ directory and try again.",
            404
        )

    def _run_training():
        global _is_training, _model, _metadata
        try:
            _is_training = True
            # Import here to avoid circular issues
            from train_model import train
            result = train(
                dataset_path=str(dataset_path),
                target_col=target_col,
                url_col=url_col,
            )
            # Reload model
            load_model()
            logger.info("Training completed. Best model: %s", result.get("selected_model"))
        except Exception as e:
            logger.error("Training thread failed: %s", e)
        finally:
            _is_training = False

    thread = threading.Thread(target=_run_training, daemon=True)
    thread.start()

    return jsonify({
        "status": "started",
        "message": (
            f"Training started on dataset '{dataset}' "
            f"with target column '{target_col}'. "
            "Check /api/health for model readiness."
        ),
    }), 202


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
# Initialize DB and model on module import (critical for Vercel & serverless WSGI)
init_db()
load_model()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    logger.info("Starting PhishGuard on http://localhost:%d", port)
    app.run(debug=True, host="0.0.0.0", port=port, use_reloader=False)
