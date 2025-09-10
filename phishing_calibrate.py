"""Calibrate the existing XGBoost joblib model using Platt scaling (sigmoid) and save a calibrated wrapper.

Produces:
- Phishing_XGB_Model_tuned_balanced_calibrated.joblib
- calibration_report.json
"""
import os
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.calibration import CalibratedClassifierCV
from sklearn.linear_model import LogisticRegression

BASE = os.path.dirname(__file__)
PHISHING_DIR = os.path.join(BASE, 'Phishing_ML', 'Phishing-Website-Detection-by-Machine-Learning-Techniques')
DATA_DIR = os.path.join(PHISHING_DIR, 'DataFiles')
JOBLIB_PATH = os.path.join(PHISHING_DIR, 'Phishing_XGB_Model_tuned_balanced.joblib')
CALIB_JOBLIB = os.path.join(PHISHING_DIR, 'Phishing_XGB_Model_tuned_balanced_calibrated.joblib')
REPORT_PATH = os.path.join(BASE, 'logs', 'calibration_report.json')

# Load datasets
phish_csv = os.path.join(DATA_DIR, '4.phishing.csv')
legit_csv = os.path.join(DATA_DIR, '3.legitimate.csv')

print('Loading data...')
ph = pd.read_csv(phish_csv, header=None, names=['url'])
lg = pd.read_csv(legit_csv, header=None, names=['url'])
ph['label'] = 1
lg['label'] = 0

df = pd.concat([ph, lg], ignore_index=True)

df = df.sample(frac=1, random_state=42).reset_index(drop=True)

# Import backend feature extractor
import sys
sys.path.append(os.path.join(PHISHING_DIR))
try:
    from URLFeatureExtraction import featureExtraction as original_feature_extraction
    USE_ORIGINAL = True
except Exception:
    USE_ORIGINAL = False

# Import backend app wrapper if available to use its offline extractor
try:
    import importlib.util
    backend_app_path = os.path.join(BASE, 'cipher cop', 'backend', 'app.py')
    if os.path.exists(backend_app_path):
        spec = importlib.util.spec_from_file_location('backend_app', backend_app_path)
        backend_app = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(backend_app)
        feature_extractor = getattr(backend_app, 'featureExtraction')
        normalize = getattr(backend_app, 'normalize_features_for_model')
        print('Using backend featureExtraction from app.py')
    else:
        raise ImportError('backend app.py not found')
except Exception:
    # fallback to simple local extractor definition here
    def feature_extractor(url):
        # minimal mimic of fallback_featureExtraction from backend
        from urllib.parse import urlparse
        p = urlparse(url)
        domain = p.hostname or ''
        path = p.path or ''
        query = p.query or ''
        feats = [len(url), len(domain), len(path), len(query), 1 if p.scheme=='https' else 0, 1 if '-' in domain else 0, 1 if any(ch.isdigit() for ch in domain) else 0, 1 if False else 0, 0, 0]
        while len(feats) < 16:
            feats.append(0)
        return feats
    normalize = lambda f, m: f
    print('Using local fallback feature extractor')

# Build feature matrix
print('Extracting features for', len(df), 'rows...')
X = []
for u in df['url'].tolist():
    try:
        feats = feature_extractor(u)
    except Exception:
        feats = feature_extractor(u)
    X.append(feats)
X = np.array(X)
y = df['label'].values

# Load joblib model
print('Loading joblib model:', JOBLIB_PATH)
try:
    model = joblib.load(JOBLIB_PATH)
except Exception as e:
    import traceback
    print('ERROR loading joblib model:', e)
    traceback.print_exc()
    raise

# Split
X_train, X_hold, y_train, y_hold = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# Fit CalibratedClassifierCV (sigmoid)
print('Fitting calibrated classifier...')
try:
    calibrator = CalibratedClassifierCV(base_estimator=model, method='sigmoid', cv='prefit')
    calibrator.fit(X_hold, y_hold)
except Exception as e:
    import traceback
    print('ERROR during calibration:', e)
    traceback.print_exc()
    raise

# Save calibrated model
os.makedirs(os.path.dirname(CALIB_JOBLIB), exist_ok=True)
joblib.dump(calibrator, CALIB_JOBLIB)

# Report simple holdout metrics
from sklearn.metrics import precision_score, recall_score, f1_score
probs = calibrator.predict_proba(X_hold)[:,1]
preds = (probs >= 0.5).astype(int)
report = {
    'holdout_precision_0.5': float(precision_score(y_hold, preds)),
    'holdout_recall_0.5': float(recall_score(y_hold, preds)),
    'holdout_f1_0.5': float(f1_score(y_hold, preds))
}

os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
import json
with open(REPORT_PATH, 'w', encoding='utf-8') as f:
    json.dump(report, f, indent=2)

print('Calibration done. Saved:', CALIB_JOBLIB)
print('Report:', report)
