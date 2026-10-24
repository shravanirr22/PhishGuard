# PhishGuard — AI-Powered Phishing Website Detection System

A complete, full-stack machine learning application for detecting phishing websites in real time using URL feature analysis.

---

## Features

- **22-feature URL analysis** — URL length, entropy, IP detection, HTTPS, suspicious keywords, subdomains, and more
- **3 ML models** — Logistic Regression, Decision Tree, Random Forest
- **Flask REST API** with 6 endpoints
- **SQLite scan history** with parameter redaction
- **5-page responsive dashboard** with dark cybersecurity theme
- **Real Chart.js metrics** — never fabricated
- **Automated pytest suite** — 40+ tests

---

## Prerequisites

- Python 3.11+
- pip

---

## Installation

### 1. Clone / Navigate to project

```bash
cd "Phishing Website Detection"
```

### 2. Create virtual environment (recommended)

```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## Dataset Setup

Place a phishing detection CSV dataset in the `data/` folder.

### Recommended Datasets

| Dataset | Format | Target Column | URL |
|---------|--------|---------------|-----|
| UCI Phishing Website Features | Pre-extracted numeric features | `Result` | https://archive.ics.uci.edu/dataset/327/phishing+websites |
| Kaggle Phishing Dataset | Pre-extracted features | `class` or `label` | https://www.kaggle.com/datasets/eswarchandt/phishing-website-detector |
| PhiUSIIL Phishing URL | Raw URLs | `label` | https://archive.ics.uci.edu/dataset/967 |

### Download UCI Dataset (Quick Start)

1. Visit https://archive.ics.uci.edu/dataset/327/phishing+websites
2. Download the ZIP and extract the CSV
3. Place it as `data/phishing_dataset.csv`

---

## Model Training

### Pre-extracted feature dataset (e.g., UCI):
```bash
python train_model.py --dataset data/phishing_dataset.csv --target Result
```

### Raw URL dataset:
```bash
python train_model.py --dataset data/phishing_urls.csv --target label --url-column url
```

### Training options:
```bash
python train_model.py --help
```

The training script will:
1. Load and validate the dataset
2. Extract features (if URL column specified)
3. Train Logistic Regression, Decision Tree, Random Forest
4. Select the best model by F1-score
5. Save model to `models/phishguard_model.joblib`
6. Save metadata to `models/model_metadata.json`
7. Save evaluation plots to `models/plots/`

---

## Running the Application

```bash
python app.py
```

Then open your browser at: **http://localhost:5000**

---

## Pages

| Page | URL | Description |
|------|-----|-------------|
| Dashboard | `/` | Hero stats, quick scan, how-it-works |
| URL Scanner | `/scanner` | Full URL analysis with detailed report |
| Model Performance | `/performance` | Real training metrics and Chart.js charts |
| Scan History | `/history` | All previous scans with filter/clear |
| About | `/about` | Project details, architecture, dataset setup |

---

## API Documentation

### `GET /api/health`
Returns model readiness status.

**Response:**
```json
{
  "status": "ok",
  "model_ready": true,
  "model_name": "Random Forest",
  "trained_on": "2024-01-01T12:00:00",
  "timestamp": "2024-01-01T13:00:00"
}
```

---

### `POST /api/predict`
Analyze a URL for phishing.

**Request:**
```json
{ "url": "https://example.com" }
```

**Response (with model):**
```json
{
  "status": "ok",
  "display_url": "https://example.com",
  "prediction": "Legitimate",
  "is_phishing": false,
  "confidence": 87.3,
  "features": { "has_https": 1, "url_length": 19, ... },
  "explanations": [],
  "model_used": "Random Forest",
  "disclaimer": "ML prediction — not a guarantee..."
}
```

**Response (no model, 503):**
```json
{
  "status": "no_model",
  "message": "No trained model available..."
}
```

---

### `GET /api/metrics`
Returns real evaluation metrics from training.

---

### `GET /api/history?limit=100`
Returns recent scan history.

---

### `DELETE /api/history`
Clears all scan history.

---

### `POST /api/train`
Starts model training on a configured dataset.

**Request:**
```json
{
  "dataset": "data/phishing_dataset.csv",
  "target_column": "Result",
  "url_column": null
}
```

**Response (202 Accepted):**
```json
{
  "status": "started",
  "message": "Training started..."
}
```

---

## Running Tests

```bash
python -m pytest tests/ -v
```

### Test coverage includes:
- Feature extraction (40+ cases)
- Invalid and malformed URLs
- IP address detection
- HTTPS/HTTP detection
- Suspicious word detection
- API endpoint tests
- Security (path traversal, parameter injection)
- History save/retrieve/delete
- No-model state

---

## Project Structure

```
Phishing Website Detection/
├── app.py                    # Flask application
├── train_model.py            # ML training pipeline
├── feature_extraction.py     # URL feature extraction
├── requirements.txt
├── .env.example
├── .gitignore
├── README.md
├── models/
│   ├── phishguard_model.joblib   # Trained model (after training)
│   ├── model_metadata.json       # Evaluation results
│   └── plots/                    # Training plots
├── data/
│   └── phishing_dataset.csv      # Your dataset (not committed)
├── database/
│   └── phishguard.db             # SQLite scan history
├── templates/
│   ├── index.html
│   ├── scanner.html
│   ├── performance.html
│   ├── history.html
│   └── about.html
├── static/
│   ├── css/main.css
│   └── js/
│       ├── main.js
│       ├── scanner.js
│       ├── performance.js
│       └── history.js
└── tests/
    ├── test_feature_extraction.py
    └── test_api.py
```

---

## Common Issues

| Problem | Solution |
|---------|----------|
| `python: command not found` | Use `python3` or add Python to PATH |
| `No module named flask` | Run `pip install -r requirements.txt` |
| Port 5000 in use | Set `PORT=5001` environment variable |
| Model not found | Run `python train_model.py --dataset ...` first |
| Dataset column error | Check the target column name matches `--target` |
| Training slow | Large datasets with URL extraction take time; use pre-extracted feature datasets for speed |

---

## Limitations

- URL-only analysis — cannot detect phishing via page content or visual similarity
- Model accuracy depends on dataset quality and size
- Results are probabilistic predictions, not security guarantees
- Newly created phishing domains may not be flagged if URL structure looks clean

---

## Disclaimer

PhishGuard is built for **educational and research purposes**. It is not a replacement for professional security tools. Always exercise caution when browsing online.
