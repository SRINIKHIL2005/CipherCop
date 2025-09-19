# CipherCop

A practical phishing and malware detection system composed of:

- A Flask backend that scores websites using heuristics, Google Safe Browsing, optional LLM assistance, and ML models (XGBoost).
- A Chrome extension that performs real‑time URL checks and warns or blocks based on backend results.
- A lightweight frontend for local validation and dashboard views.
- Reproducible ML training/tuning scripts and model artifacts.

This README documents how to run, configure, and develop the system without fluff.

## Table of contents

- Overview
- System architecture
- Prerequisites
- Setup and local run
  - Backend (Flask)
  - Frontend (static/Vite)
  - Chrome extension
- Configuration (env vars)
- API overview
- Models and training
- Repository structure
- Troubleshooting
- Security notes and licensing

## Overview

The backend exposes REST endpoints to classify websites and APKs. The Chrome extension calls the backend on navigation and injects warnings with configurable intensity. The system prefers local, deterministic URL feature extraction (offline‑first) to reduce false positives and flaky network dependencies; Safe Browsing and optional LLM checks are layered on top.

## System architecture

- Backend (Flask): threat scoring pipeline
  - URL heuristics (domain, path, TLD, length, patterns)
  - Optional URL HTML/WAI features when accessible
  - Safe Browsing lookups (if API key configured)
  - ML phishing classifier (XGBoost JSON/joblib)
  - Optional Gemini (LLM) summary signal
  - SQLite persistence for users, sessions, scans, and extension analytics
- Chrome extension: background monitor + content overlay + popup UI
  - Calls `/analyze/website`, logs visits to `/extension/log-visit`
  - Warn/Block thresholds based on combined risk
- Frontend: static HTML/Vite pages for local testing/dashboard
- ML: scripts for training, tuning, and exporting XGBoost models

## Prerequisites

- Windows, macOS, or Linux
- Python 3.10+ (3.13 supported)
- Node.js 18+ (only if using the Vite dev server)
- Google Chrome (for the extension)

Optional external services:
- Google Safe Browsing API key
- Google Generative AI (Gemini) API key (backend works without it)

## Setup and local run

### Backend (Flask)

From the repository root in a Windows cmd shell:

- cd "cipher cop\backend"
- python -m venv .venv
- .venv\Scripts\activate
- pip install -r requirements.txt
- set FLASK_ENV=development
- python app.py

The API will run at http://localhost:5000

Notes
- The backend creates/uses `ciphercop.db` in the working directory and applies lightweight migrations at startup if it detects older schemas.
- Permissive CORS is enabled for local development.

### Frontend (static/Vite)

Option A — static serve (no build):
- cd "cipher cop\frontend"
- npm run serve:static
- Open http://localhost:3001

Option B — Vite dev server:
- cd "cipher cop\frontend"
- npm install
- npm run dev
- Open the dev URL (commonly http://localhost:5173)

### Chrome extension

- Start the backend first (http://localhost:5000)
- In Chrome: open chrome://extensions
- Toggle on “Developer mode”
- Click “Load unpacked” and select the `chrome-extension` directory
- Navigate to a few benign/malicious test URLs to see the overlay behavior

## Configuration (env vars)

All are optional unless stated.

- GOOGLE_SAFE_BROWSING_API_KEY: Enables Safe Browsing checks.
- GOOGLE_API_KEY: Enables Gemini‑based analysis; without it, the backend uses heuristics/ML only.
- FRONTEND_URL: If set, GET / redirects to this URL; otherwise the backend probes common dev ports.
- ML_THRESHOLD: Float (0..1), default 0.79; influences how model scores are interpreted.
- EXTRACTION_MODE: OFFLINE_FIRST (default) | REMOTE_FIRST | OFFLINE_ONLY; controls URL feature extraction routing.
- ALLOW_REMOTE_EXTRACTION: 1 (default) allows remote extractor when DNS resolves; set 0 for fully local extraction.

Create a `.env` file in `cipher cop/backend/` to store local secrets; do not commit real keys.

## API overview

Selected endpoints (see `cipher cop/backend/app.py` for details):

- POST `/analyze/website` { url: string }
  - Returns verdict, combined risk score, component signals (ML, Safe Browsing, heuristic) and metadata.
- POST `/analyze/adult-content` { url: string, userAge: number }
  - Returns detection flag and recommendation (used by the extension).
- POST `/analyze/app`
  - Accepts APK upload or text metadata; returns malware classification when model is available.
- GET `/health`
  - Returns server and model load status; used for smoke checks.

## Models and training

Preferred phishing model format: XGBoost Booster JSON for stability across xgboost versions; joblib models are supported as fallbacks.

Artifacts are read from:
`Phishing_ML/Phishing-Website-Detection-by-Machine-Learning-Techniques/`

Common workflows (run from repository root):

- Retrain with current extractor and export JSON/joblib:
  - python phishing_retrain_current_extractor.py
- Tuning runs (current extractor / class balance):
  - python phishing_tune_current_extractor.py
  - python phishing_tune_balance.py

Data files are expected under `Phishing_ML/.../DataFiles/` (e.g., `3.legitimate.csv`, `4.phishing.csv`).

APK malware model: optional XGBoost model under `Models/APK/Models/APKMalwareDetection/app/model/` (JSON preferred over pickle).

## Repository structure

High‑level map (selected):

- `cipher cop/backend/`
  - `app.py` — REST API service and threat pipeline
  - `database.py` — SQLite schema, analytics, and logging
  - `heuristics/` — allow/deny lists and scoring helpers
  - `requirements.txt`
- `cipher cop/frontend/` — static pages and optional Vite config
- `chrome-extension/` — background/content/popup and manifest
- `Phishing_ML/Phishing-Website-Detection-by-Machine-Learning-Techniques/` — feature extractor, data, models
- `logs/` — runtime logs
- Root training/tuning scripts — e.g., `phishing_retrain_current_extractor.py`, `phishing_tune_balance.py`

There is also an older `backend/` folder in the root; the active backend used by tasks and the extension is `cipher cop/backend/`.

## Troubleshooting

- Safe Browsing not active: ensure `GOOGLE_SAFE_BROWSING_API_KEY` is set; otherwise the result will omit that signal.
- Internal URLs: the backend intentionally skips localhost/192.168.* to avoid self‑analysis loops.
- Model loading errors: prefer Booster JSON artifacts; confirm paths in `app.py` align with your model locations.
- Vite plugin errors: install dependencies inside `cipher cop/frontend/` or use the static serve option.
- SQLite schema mismatches: run the backend once to apply the small migrations; they add missing columns for older DB files.

## Security notes and licensing

- Do not commit real API keys. Use `.env` locally; use secret managers in production.
- Review and maintain allowlist/blacklist files in `cipher cop/backend/heuristics/` to fit your environment.
- No explicit license file is present at the root as of this revision. Add a LICENSE before distributing.
