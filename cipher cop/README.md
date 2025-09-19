# CipherCop

An end‑to‑end phishing and malware detection system consisting of a Flask backend, a Chrome extension for real‑time URL protection, a lightweight frontend dashboard, and reproducible ML training scripts. The backend combines heuristic analysis, Google Safe Browsing lookups, optional LLM assistance, and ML models (XGBoost) to score websites and APKs.

## Contents

- Overview
- Architecture
- Prerequisites
- Setup and local run
  - Backend (Flask)
  - Frontend (static/Vite)
  - Chrome extension
- Configuration
- Models and training
- Logs and data
- Testing
- Troubleshooting
- Notes on security and licensing

## Overview

CipherCop provides:

- Real‑time website risk analysis via REST endpoints and a Chrome extension.
- Heuristic and reputation checks (domain, HTML, URL patterns) with Safe Browsing.
- ML phishing model with offline‑first feature extraction to avoid brittle network calls.
- APK file and text‑metadata analysis with an XGBoost malware model when available.
- A simple dashboard (static files) for local validation.

## Architecture

Top‑level components of this repository:

- Backend (Flask): `cipher cop/backend/`
  - `app.py`: main API service (website, adult content, APK analysis, extension logging)
  - `database.py`: SQLite schema and helpers (users, sessions, logs, analytics)
  - `heuristics/`: allow/deny lists and scoring utilities
  - `requirements.txt`: Python dependencies
- Frontend (static/Vite): `cipher cop/frontend/`
  - `index.html`, `dashboard.html`, `main.jsx`, `vite.config.js`
  - `package.json`: optional dev server via Vite or static serve
- Chrome extension: `chrome-extension/`
  - `manifest.json`, `background.js`, `content.js`, `popup.html`, `popup.js`
- ML artifacts and scripts:
  - `Phishing_ML/Phishing-Website-Detection-by-Machine-Learning-Techniques/`: datasets, feature extractor, saved models (JSON/joblib)
  - Root scripts like `phishing_retrain_current_extractor.py`, `phishing_tune_balance.py`, etc.
- Logs: `logs/`

## Prerequisites

- Python 3.10+ (3.13 supported)
- Node.js 18+ (only if using the Vite dev server)
- Google Chrome (for the extension)

Optional external services:
- Google Safe Browsing API key
- Google Generative AI (Gemini) API key (for LLM‑assisted summaries; system works without it)

## Setup and local run

### 1) Backend (Flask)

From the repo root in a terminal:

- Create and activate a virtual environment (recommended)
- Install dependencies
- Run the server

On Windows (cmd):

- cd "cipher cop\backend"
- python -m venv .venv
- .venv\Scripts\activate
- pip install -r requirements.txt
- set FLASK_ENV=development
- python app.py

By default the API listens on http://localhost:5000

### 2) Frontend (static/Vite)

This repository includes static HTML pages that can be opened directly, and a Vite config for a dev server if preferred.

Option A — static serve (no build):
- cd "cipher cop\frontend"
- npm run serve:static
- Open http://localhost:3001

Option B — Vite dev server:
- Ensure @vitejs/plugin-react is installed (see the root package.json). If not, install it in this folder.
- cd "cipher cop\frontend"
- npm install
- npm run dev
- Open the dev URL (commonly http://localhost:5173)

Note: The backend probes common frontend ports and may redirect to a detected UI during development.

### 3) Chrome extension

- Start the backend first (http://localhost:5000)
- Open chrome://extensions
- Enable “Developer mode”
- Click “Load unpacked” and select the `chrome-extension` directory
- The extension’s background script points to http://localhost:5000; ensure your backend is accessible on that port

## Configuration

Environment variables consumed by the backend (all optional unless stated):

- GOOGLE_SAFE_BROWSING_API_KEY: Safe Browsing requests. Without it, Safe Browsing is skipped.
- GOOGLE_API_KEY: Gemini/Generative AI key. Without it, the backend falls back to local heuristics.
- FRONTEND_URL: Force redirect for GET /. If not set, the backend probes common frontend ports.
- ML_THRESHOLD: Float (0..1) default 0.79. Controls model sensitivity when building the final verdict.
- EXTRACTION_MODE: OFFLINE_FIRST (default) | REMOTE_FIRST | OFFLINE_ONLY. Controls URL feature extraction strategy.
- ALLOW_REMOTE_EXTRACTION: 1 (default) to allow networked extraction when DNS resolves; set 0 to keep extraction local.

The backend stores a SQLite database named `ciphercop.db` in the backend working directory. Lightweight migrations run at startup to add missing columns for older DB files.

## Models and training

Saved phishing models are loaded from `Phishing_ML/Phishing-Website-Detection-by-Machine-Learning-Techniques/` in this repository. Preferred formats:

- XGBoost Booster JSON (no pickle compatibility issues)
- joblib model as a fallback

Key scripts (run from repo root):

- `phishing_retrain_current_extractor.py`: Retrain using project’s URLFeatureExtraction; saves JSON and joblib.
- `phishing_tune_current_extractor.py` / `phishing_tune_balance.py`: Hyper‑parameter tuning runs.

Data
- Expected CSVs live under `Phishing_ML/.../DataFiles/` (e.g., 3.legitimate.csv, 4.phishing.csv)

Notes
- xgboost must match the saved artifact format; Booster JSON avoids most version issues.
- The backend’s feature pipeline normalizes vectors defensively to the model’s expected length.

## Logs and data

- Runtime logs are under `logs/` (various .log files).
- Extension and API activity is persisted to SQLite (`ciphercop.db`) with tables covering scans, threats, and usage statistics.

## Testing

- Backend imports can be sanity‑checked via the VS Code task “Import backend app check”.
- Unit tests (if present) live under `cipher cop/backend/tests/`.
- Manual smoke tests:
  - POST http://localhost:5000/analyze/website with {"url": "https://example.com"}
  - Load a known benign and a known test phishing domain; observe extension behavior

## Troubleshooting

- Safe Browsing disabled: If GOOGLE_SAFE_BROWSING_API_KEY is not set, Safe Browsing checks are skipped.
- Internal/localhost URLs: The backend intentionally skips analysis for internal hosts (localhost, 127.0.0.1, 192.168.*) to prevent self‑analysis loops.
- Frontend plugin errors: If Vite complains about @vitejs/plugin-react, install it in `cipher cop/frontend` or use the static serve option.
- Model not found: The backend runs with heuristics only if no model is available. Place model artifacts in `Phishing_ML/...` as per paths in `app.py`.
- xgboost errors: Prefer JSON Booster models to avoid pickled version mismatches.
- CORS: The backend enables permissive CORS by default; if you reverse proxy, ensure headers are preserved.

## Notes on security and licensing

- Do not commit real API keys. Use a .env file locally; production should use secure secret management.
- Review allowlist/blacklist heuristics under `cipher cop/backend/heuristics` before deploying.
- License: no license file is present in this directory. If you intend to distribute, add an explicit LICENSE at the repository root.
