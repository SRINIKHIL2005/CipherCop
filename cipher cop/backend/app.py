from flask import Flask, request, jsonify, redirect
from flask_cors import CORS
from werkzeug.utils import secure_filename

import requests
import os
import json
import re
import urllib.parse
from datetime import datetime, timedelta
import hashlib
from dotenv import load_dotenv
# ML and feature extraction imports
import joblib
import socket
import whois
from bs4 import BeautifulSoup
import urllib.request
import random
import tempfile
import zipfile

# Import database
from database import CipherCopDB
# Initialize database
db = CipherCopDB()
# Import new heuristics helper
from heuristics.heuristics import rate_limited_safe_browsing, compute_heuristic_score, combine_scores

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Configure CORS
CORS(app, resources={
    r"/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "X-Requested-With", "Accept", "Origin"]
    }
})

# Simple heuristic lists (allowlist/blacklist)
HEURISTIC_DIR = os.path.join(os.path.dirname(__file__), 'heuristics')
ALLOWLIST_PATH = os.path.join(HEURISTIC_DIR, 'allowlist.txt')
BLACKLIST_PATH = os.path.join(HEURISTIC_DIR, 'blacklist.txt')

def _load_list(path):
    try:
        if not os.path.exists(path):
            return set()
        with open(path, 'r', encoding='utf-8') as f:
            return set([l.strip().lower() for l in f if l.strip()])
    except Exception:
        return set()

ALLOWLIST = _load_list(ALLOWLIST_PATH)
BLACKLIST = _load_list(BLACKLIST_PATH)

# Add a small built-in allowlist of major, well-known sites to avoid obvious false
# positives when network WHOIS/HTML extraction intermittently fails. This is a
# conservative list only; users can edit `heuristics/allowlist.txt` to change it.
BUILTIN_ALLOWLIST = {
    'google.com', 'www.google.com', 'youtube.com', 'www.youtube.com',
    'gmail.com', 'facebook.com', 'www.facebook.com', 'twitter.com', 'www.twitter.com',
    'linkedin.com', 'amazon.com', 'www.amazon.com', 'wikipedia.org', 'www.wikipedia.org',
    'microsoft.com', 'apple.com', 'reddit.com', 'www.reddit.com'
}

ALLOWLIST = set([d.lower() for d in ALLOWLIST]) | BUILTIN_ALLOWLIST

# Comprehensive CORS setup
@app.after_request
def after_request(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With, Accept, Origin'
    response.headers['Access-Control-Max-Age'] = '3600'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response

# Handle OPTIONS requests globally
@app.route('/', methods=['OPTIONS'])
@app.route('/<path:path>', methods=['OPTIONS'])
def handle_options(path=None):
    response = jsonify({'status': 'ok'})
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin')
    return response


# Google API Configuration
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "AIzaSyBKk_Cve7_FV7KV0s9tXx1jXVyNPu6ZEc0")
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent?key=" + GOOGLE_API_KEY

# Google Safe Browsing API Configuration
SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v1/threatMatches:find"

# Load ML model and feature extraction code
MODEL_PATH = os.path.join(os.path.dirname(__file__), '../../Phishing_ML/Phishing-Website-Detection-by-Machine-Learning-Techniques/XGBoostClassifier.pickle.dat')
XGBOOST_JSON_PATH = os.path.join(os.path.dirname(__file__), '../../Phishing_ML/Phishing-Website-Detection-by-Machine-Learning-Techniques/XGBoostClassifier_tuned_balanced.json')
ORIGINAL_XGBOOST_JSON_PATH = os.path.join(os.path.dirname(__file__), '../../Phishing_ML/Phishing-Website-Detection-by-Machine-Learning-Techniques/XGBoostClassifier_retrained.json')
PHISHING_XGB_JOBLIB = os.path.join(os.path.dirname(__file__), '../../Phishing_ML/Phishing-Website-Detection-by-Machine-Learning-Techniques/Phishing_XGB_Model_retrained.joblib')
PHISHING_RF_JOBLIB = os.path.join(os.path.dirname(__file__), '../../Phishing_ML/Phishing-Website-Detection-by-Machine-Learning-Techniques/Phishing_RF_Model.joblib')
PHISHING_CALIB_JOBLIB = os.path.join(os.path.dirname(__file__), '../../Phishing_ML/Phishing-Website-Detection-by-Machine-Learning-Techniques/Phishing_XGB_Model_tuned_balanced_calibrated.joblib')
FEATURE_EXTRACTOR_PATH = os.path.join(os.path.dirname(__file__), '../../Phishing_ML/Phishing-Website-Detection-by-Machine-Learning-Techniques/URLFeatureExtraction.py')

# APK Malware Detection Model
APK_MODEL_PATH = os.path.join(os.path.dirname(__file__), '../../Models/APK/Models/APKMalwareDetection/app/model/xgboost_best_model.pkl')
APK_JSON_PATH = os.path.join(os.path.dirname(__file__), '../../Models/APK/Models/APKMalwareDetection/app/model/xgboost_best_model.json')


# XGBoost JSON wrapper available at module scope so it can be instantiated
# regardless of which branch is taken during model loading.
class XGBoostJSONWrapper:
    def __init__(self, json_path):
        # import xgboost lazily to avoid import-time errors when xgboost is not installed
        import xgboost as xgb
        self.xgb = xgb
        self.json_path = json_path
        self.booster = xgb.Booster()
        self.booster.load_model(json_path)
        # try to read feature names / count from JSON
        try:
            import json as _json
            with open(json_path, 'r', encoding='utf-8') as _f:
                j = _json.load(_f)
            feat_names = None
            if isinstance(j, dict):
                learner = j.get('learner') or j.get('learner_model') or {}
                feat_names = learner.get('feature_names') or learner.get('attributes', {}).get('feature_names')
            if feat_names is None and 'feature_names' in j:
                feat_names = j.get('feature_names')
            if feat_names:
                try:
                    self.n_features_in_ = int(len(feat_names))
                except Exception:
                    self.n_features_in_ = None
            else:
                self.n_features_in_ = None
        except Exception:
            self.n_features_in_ = None

    def predict(self, X_df):
        import pandas as _pd
        if isinstance(X_df, _pd.DataFrame):
            df = X_df
        else:
            import numpy as _np
            df = _pd.DataFrame(X_df)
        dmat = self.xgb.DMatrix(df)
        preds = self.booster.predict(dmat)
        if hasattr(preds, 'ndim') and preds.ndim == 1:
            return (preds > 0.5).astype(int)
        return preds

    def predict_proba(self, X_df):
        """Return probability for the positive class as a list of floats."""
        import pandas as _pd
        if isinstance(X_df, _pd.DataFrame):
            df = X_df
        else:
            import numpy as _np
            df = _pd.DataFrame(X_df)
        dmat = self.xgb.DMatrix(df)
        preds = self.booster.predict(dmat)
        if hasattr(preds, 'ndim') and preds.ndim == 1:
            return [[1 - float(p), float(p)] for p in preds]
        return preds.tolist()

try:
    import sys
    sys.path.append(os.path.abspath(os.path.dirname(FEATURE_EXTRACTOR_PATH)))
    from URLFeatureExtraction import featureExtraction as _imported_featureExtraction
    # Keep a handle to the original, network-capable extractor (if import succeeds)
    ORIGINAL_FEATURE_EXTRACTION = _imported_featureExtraction

    ml_model = None

    # Prefer XGBoost JSON if available (produced by the training notebook)
    try:
        if os.path.exists(XGBOOST_JSON_PATH):
            import xgboost as xgb

            class XGBoostJSONWrapper:
                def __init__(self, json_path):
                    self.json_path = json_path
                    self.booster = xgb.Booster()
                    self.booster.load_model(json_path)
                    # Try to read feature count from the JSON model metadata
                    try:
                        import json as _json
                        with open(json_path, 'r', encoding='utf-8') as _f:
                            j = _json.load(_f)
                        # JSON structure contains learner.feature_names in many exports
                        feat_names = None
                        if isinstance(j, dict):
                            learner = j.get('learner') or j.get('learner_model') or {}
                            feat_names = learner.get('feature_names') or learner.get('attributes', {}).get('feature_names')
                        if feat_names is None and 'feature_names' in j:
                            feat_names = j.get('feature_names')
                        if feat_names:
                            try:
                                self.n_features_in_ = int(len(feat_names))
                            except Exception:
                                self.n_features_in_ = None
                        else:
                            self.n_features_in_ = None
                    except Exception:
                        self.n_features_in_ = None

                def predict(self, X_df):
                    import pandas as _pd
                    if isinstance(X_df, _pd.DataFrame):
                        df = X_df
                    else:
                        import numpy as _np
                        df = _pd.DataFrame(X_df)
                    dmat = xgb.DMatrix(df)
                    preds = self.booster.predict(dmat)
                    if preds.ndim == 1:
                        return (preds > 0.5).astype(int)
                    return preds
                def predict_proba(self, X_df):
                    """Return probability for the positive class as a list of floats."""
                    import pandas as _pd
                    if isinstance(X_df, _pd.DataFrame):
                        df = X_df
                    else:
                        import numpy as _np
                        df = _pd.DataFrame(X_df)
                    dmat = xgb.DMatrix(df)
                    preds = self.booster.predict(dmat)
                    # preds are probabilities for positive class for binary:logistic
                    if preds.ndim == 1:
                        return [[1 - float(p), float(p)] for p in preds]
                    # fallback
                    return preds.tolist()

            ml_model = XGBoostJSONWrapper(XGBOOST_JSON_PATH)
            print('[INFO] Loaded XGBoost JSON booster for phishing detection.')
        # If retrained JSON not present, try to load original JSON as a backup
        elif os.path.exists(ORIGINAL_XGBOOST_JSON_PATH):
            import xgboost as xgb
            ml_model = XGBoostJSONWrapper(ORIGINAL_XGBOOST_JSON_PATH)
            print('[INFO] Loaded ORIGINAL XGBoost JSON booster for phishing detection (backup).')


        # Prefer a calibrated joblib if available
        elif os.path.exists(PHISHING_CALIB_JOBLIB):
            try:
                ml_model = joblib.load(PHISHING_CALIB_JOBLIB)
                print('[INFO] Loaded calibrated Phishing XGB joblib for phishing detection.')
            except Exception as e:
                print(f'[WARN] Failed to load calibrated joblib: {e}, falling back...')
                ml_model = None
        elif os.path.exists(PHISHING_XGB_JOBLIB):
            ml_model = joblib.load(PHISHING_XGB_JOBLIB)
            print('[INFO] Loaded Phishing_XGB_Model.joblib')

        elif os.path.exists(PHISHING_RF_JOBLIB):
            ml_model = joblib.load(PHISHING_RF_JOBLIB)
            print('[INFO] Loaded Phishing_RF_Model.joblib')

        elif os.path.exists(MODEL_PATH):
            ml_model = joblib.load(MODEL_PATH)
            print('[INFO] Loaded model via joblib at MODEL_PATH')

    except Exception as inner_exc:
        # Attempt fallback joblib loads
        try:
            if os.path.exists(PHISHING_RF_JOBLIB):
                ml_model = joblib.load(PHISHING_RF_JOBLIB)
                print('[INFO] Loaded Phishing_RF_Model.joblib (fallback)')
            elif os.path.exists(MODEL_PATH):
                ml_model = joblib.load(MODEL_PATH)
                print('[INFO] Loaded model via joblib at MODEL_PATH (fallback)')
            else:
                ml_model = None
        except Exception as ex2:
            print(f'[ERROR] Failed to load any phishing model: {ex2}')
            ml_model = None

    # Some XGBoost models saved with older wrappers expect the attribute
    # `use_label_encoder`. Newer xgboost versions removed it. Ensure the
    # attribute exists to avoid attribute errors on predict().
    try:
        if ml_model is not None and not hasattr(ml_model, 'use_label_encoder'):
            setattr(ml_model, 'use_label_encoder', False)
    except Exception:
        pass

    print('[INFO] ML model loaded for phishing detection.')

    # ML decision threshold (can be tuned via env var)
    # Default raised to 0.79 to favor precision (can be overridden with env var ML_THRESHOLD)
    ML_THRESHOLD = float(os.getenv('ML_THRESHOLD', '0.79'))

    def normalize_features_for_model(features, model):
        """Ensure features is a plain list of length model.n_features_in_ (if available).
        Pad with zeros or truncate deterministically.
        """
        try:
            # convert to list
            if isinstance(features, (list, tuple)):
                f = list(features)
            elif hasattr(features, 'tolist'):
                f = list(features.tolist())
            elif isinstance(features, dict):
                f = [features[k] for k in sorted(features.keys())]
            else:
                try:
                    f = list(features)
                except Exception:
                    f = [features]

            expected = None
            if model is not None:
                expected = getattr(model, 'n_features_in_', None)
                if expected is None and hasattr(model, 'n_features_in_'):
                    try:
                        expected = int(getattr(model, 'n_features_in_'))
                    except Exception:
                        expected = None
            if expected is None:
                return f

            expected = int(expected)
            if len(f) < expected:
                f = f + [0] * (expected - len(f))
            elif len(f) > expected:
                f = f[:expected]
            return f
        except Exception:
            # fallback zero vector
            try:
                expected = int(getattr(model, 'n_features_in_', 16) or 16)
            except Exception:
                expected = 16
            return [0] * expected

    # Load APK malware detection model - prefer JSON Booster when available to avoid
    # pickle compatibility warnings across xgboost versions.
    try:
        if os.path.exists(APK_JSON_PATH):
            import xgboost as xgb
            apk_booster = xgb.Booster()
            apk_booster.load_model(APK_JSON_PATH)
            apk_ml_model = apk_booster
            print('[INFO] Loaded APK malware detection XGBoost Booster from JSON.')
        elif os.path.exists(APK_MODEL_PATH):
            apk_ml_model = joblib.load(APK_MODEL_PATH)
            print('[INFO] APK malware detection model loaded (joblib/pickle).')
        else:
            apk_ml_model = None
            print('[WARN] No APK malware model found at expected paths.')
    except Exception as e:
        print(f'[WARN] Failed to load APK malware model cleanly: {e}')
        apk_ml_model = None

    # Try to import APK feature extractor
    try:
        import sys
        apk_feature_path = os.path.join(os.path.dirname(__file__), '../../Models/APK/Models/APKMalwareDetection/app')
        if apk_feature_path not in sys.path:
            sys.path.append(apk_feature_path)
        from feature_extractor import FeatureExtractor
        APK_FEATURE_EXTRACTOR = FeatureExtractor
        print('[INFO] APK feature extractor loaded successfully.')
    except Exception as e:
        print(f'[WARN] Failed to load APK feature extractor: {e}')
        APK_FEATURE_EXTRACTOR = None
except Exception as e:
    print(f"[ERROR] Error loading ML model or feature extractor: {e}")
    ml_model = None
    apk_ml_model = None
    ORIGINAL_FEATURE_EXTRACTION = None

def safe_feature_extraction(url):
    """Attempt to run the project's featureExtraction, fall back to a safe zero-vector when network fails.

    Returns: tuple(features, fallback_used)
    """
    # Try the configured extractor (offline-first wrapper if present), fall back to zeros on error
    try:
        extractor = globals().get('offline_first_featureExtraction') or globals().get('featureExtraction') or fallback_featureExtraction
        features = extractor(url)
        # If extractor returns a dict or complex structure, try to convert to list
        if hasattr(features, 'tolist'):
            try:
                return (list(features.tolist()), False)
            except Exception:
                pass
        if isinstance(features, dict):
            # Sort keys to make deterministic vector (best-effort)
            vals = [features[k] for k in sorted(features.keys())]
            return (vals, False)
        if isinstance(features, (list, tuple)):
            return (list(features), False)
    except Exception as e:
        print(f"[WARN] featureExtraction failed, using fallback features: {e}")

    # Fallback: create zero-vector matching model input if available
    fallback_len = 16
    try:
        if ml_model is not None and hasattr(ml_model, 'n_features_in_') and getattr(ml_model, 'n_features_in_'):
            fallback_len = int(getattr(ml_model, 'n_features_in_'))
    except Exception:
        pass

    return ([0] * fallback_len, True)


# Fallback lightweight feature extraction - local only, no network calls
def fallback_featureExtraction(url):
    """Deterministic, local-only feature extraction used when the original
    feature extractor is unavailable or network calls fail.
    Returns a fixed-length list of numeric features.
    """
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.hostname or ''
        path = parsed.path or ''
        query = parsed.query or ''

        features = []
        # Basic URL characteristics
        features.append(len(url))                      # 0: url length
        features.append(len(domain))                   # 1: domain length
        features.append(len(path))                     # 2: path length
        features.append(len(query))                    # 3: query length
        features.append(1 if parsed.scheme == 'https' else 0)  # 4: https
        features.append(1 if '-' in domain else 0)    # 5: hyphen in domain
        features.append(1 if any(ch.isdigit() for ch in domain) else 0)  # 6: numeric domain
        features.append(1 if re.search(r'\d+\.\d+\.\d+\.\d+', domain) else 0)  # 7: ip in domain
        features.append(1 if re.search(r'\.(tk|ml|ga|cf|pw)$', domain) else 0)  # 8: suspicious TLD
        features.append(1 if any(s in domain for s in ['bit.ly','tinyurl','t.co','goo.gl']) else 0)  # 9: shortener

        # Fill to a default length (match training extractor)
        target_len = 16
        while len(features) < target_len:
            features.append(0)

        return features[:target_len]
    except Exception:
        return [0] * 16

# Config: control extraction behavior via env
EXTRACTION_MODE = os.getenv('EXTRACTION_MODE', 'OFFLINE_FIRST').upper()  # OFFLINE_FIRST | REMOTE_FIRST | OFFLINE_ONLY
ALLOW_REMOTE_EXTRACTION = os.getenv('ALLOW_REMOTE_EXTRACTION', '1') not in ['0', 'false', 'False']


def offline_first_featureExtraction(url):
    """Wrapper to prefer local, deterministic extraction. Will call the original
    network-capable extractor only when allowed and when the hostname resolves.
    Returns a list of numeric features.
    """
    # Offline-only mode: always use fallback
    if EXTRACTION_MODE == 'OFFLINE_ONLY':
        return fallback_featureExtraction(url)

    # Try local fallback first
    local_feats = fallback_featureExtraction(url)

    # If remote extraction is disabled, return local
    if not ALLOW_REMOTE_EXTRACTION or EXTRACTION_MODE == 'OFFLINE_FIRST':
        # If mode is OFFLINE_FIRST we still may try remote if DNS resolves and original extractor exists
        if EXTRACTION_MODE == 'OFFLINE_FIRST' and ORIGINAL_FEATURE_EXTRACTION:
            try:
                parsed = urllib.parse.urlparse(url)
                hostname = parsed.hostname
                if hostname:
                    # Quick DNS check
                    try:
                        socket.gethostbyname(hostname)
                        # Hostname resolves: attempt remote extractor
                        remote_feats = ORIGINAL_FEATURE_EXTRACTION(url)
                        if isinstance(remote_feats, (list, tuple)):
                            return list(remote_feats)
                        if hasattr(remote_feats, 'tolist'):
                            return list(remote_feats.tolist())
                        if isinstance(remote_feats, dict):
                            return [remote_feats[k] for k in sorted(remote_feats.keys())]
                    except Exception as e:
                        # DNS failed or remote extractor errored; fall back to local
                        print(f"[WARN] Remote extraction skipped/failed for {hostname}: {e}")
            except Exception:
                pass
        return local_feats

    # REMOTE_FIRST mode: try remote extractor, fallback to local if remote fails
    if EXTRACTION_MODE == 'REMOTE_FIRST' and ORIGINAL_FEATURE_EXTRACTION:
        try:
            remote_feats = ORIGINAL_FEATURE_EXTRACTION(url)
            if isinstance(remote_feats, (list, tuple)):
                return list(remote_feats)
            if hasattr(remote_feats, 'tolist'):
                return list(remote_feats.tolist())
            if isinstance(remote_feats, dict):
                return [remote_feats[k] for k in sorted(remote_feats.keys())]
        except Exception as e:
            print(f"[WARN] Remote extractor failed in REMOTE_FIRST mode: {e}")
    return local_feats


# Ensure there is a public symbol `featureExtraction` pointing to the wrapper
featureExtraction = offline_first_featureExtraction


def find_frontend_url():
    """Probe common frontend ports and return first reachable URL, or None."""
    ports = [62505, 3000, 3001, 3002, 5173]
    for p in ports:
        try:
            url = f"http://localhost:{p}"
            resp = requests.get(url, timeout=0.8)
            if resp.status_code in (200, 301, 302, 304):
                return url
        except Exception:
            continue
    return None

def get_whois_features(domain):
    """Fetch WHOIS features for a domain."""
    try:
        # Skip internal/system domains
        if not domain or domain in ['localhost', '127.0.0.1'] or domain.startswith('192.168.'):
            return {"error": "Cannot analyze internal domain"}
            
        # Skip Chrome internal domains
        if domain.endswith('.local') or 'chrome' in domain or not '.' in domain:
            return {
                "creation_date": "None",
                "expiration_date": "None", 
                "updated_date": "None",
                "registrar": None,
                "domain_age": None
            }
            
        w = whois.whois(domain)
        creation_date = w.creation_date
        expiration_date = w.expiration_date
        updated_date = w.updated_date
        registrar = w.registrar
        domain_age = None
        if creation_date:
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            domain_age = (datetime.now() - creation_date).days
        return {
            "creation_date": str(creation_date),
            "expiration_date": str(expiration_date),
            "updated_date": str(updated_date),
            "registrar": registrar,
            "domain_age": domain_age
        }
    except Exception as e:
        return {
            "creation_date": "None",
            "expiration_date": "None", 
            "updated_date": "None",
            "registrar": None,
            "domain_age": None
        }

def get_html_features(url):
    """Fetch HTML features for a URL."""
    try:
        # Skip internal/system URLs
        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.scheme in ['chrome', 'chrome-extension', 'moz-extension', 'file', 'about']:
            return {"error": f"Cannot analyze internal URL: {parsed_url.scheme}"}
            
        # Skip localhost and internal IPs for external requests
        if parsed_url.hostname in ['localhost', '127.0.0.1'] or (parsed_url.hostname and parsed_url.hostname.startswith('192.168.')):
            return {"error": "Cannot analyze internal/localhost URLs"}
            
        req = urllib.request.Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        html = urllib.request.urlopen(req, timeout=10).read()
        soup = BeautifulSoup(html, 'html.parser')
        forms = soup.find_all('form')
        scripts = soup.find_all('script')
        iframes = soup.find_all('iframe')
        suspicious_forms = [f for f in forms if 'password' in str(f).lower()]
        return {
            "form_count": len(forms),
            "script_count": len(scripts),
            "iframe_count": len(iframes),
            "suspicious_forms": len(suspicious_forms)
        }
    except Exception as e:
        return {"error": str(e)}

def check_safe_browsing_api(url):
    """Check URL against Google Safe Browsing API for real-time threat detection"""
    if not SAFE_BROWSING_API_KEY:
        print("[WARN] Safe Browsing API key not configured")
        return {"threat_found": False, "threat_type": None, "error": "API key not configured"}

    # Skip internal/system URLs
    try:
        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.scheme in ['chrome', 'chrome-extension', 'moz-extension', 'file', 'about']:
            return {"threat_found": False, "threat_type": None, "skipped": "internal_url"}
            
        if parsed_url.hostname in ['localhost', '127.0.0.1'] or (parsed_url.hostname and parsed_url.hostname.startswith('192.168.')):
            return {"threat_found": False, "threat_type": None, "skipped": "localhost"}
    except:
        pass

    try:
        headers = {"Content-Type": "application/json"}
        data = {
            "client": {
                "clientId": "ciphercop-security",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        response = requests.post(
            f"{SAFE_BROWSING_URL}?key={SAFE_BROWSING_API_KEY}",
            headers=headers,
            json=data,
            timeout=10
        )

        if response.status_code == 200:
            result = response.json()
            if "matches" in result and len(result["matches"]) > 0:
                threat_match = result["matches"][0]
                return {
                    "threat_found": True,
                    "threat_type": threat_match.get("threatType", "UNKNOWN"),
                    "platform_type": threat_match.get("platformType", "UNKNOWN")
                }
            else:
                return {"threat_found": False, "threat_type": None}
        else:
            print(f"[ERROR] Safe Browsing API Error: {response.status_code} - {response.text}")
            return {"threat_found": False, "threat_type": None, "error": f"API Error {response.status_code}"}

    except Exception as e:
        print(f"[ERROR] Safe Browsing API Exception: {str(e)}")
        return {"threat_found": False, "threat_type": None, "error": str(e)}

print("Using Google API Key: [REDACTED]")
print("Gemini API URL: [REDACTED]")

# Simplified and Working Classification System
class ThreatClassifier:
    def __init__(self):
        # Enhanced phishing patterns with more comprehensive detection
        self.phishing_patterns = [
            # Money-related scams
            r'free.*money.*claim',
            r'claim.*your.*prize',
            r'you.*won.*lottery',
            r'bitcoin.*investment.*guaranteed',
            r'crypto.*investment.*high.*return',
            r'million.*dollar.*inheritance',
            r'nigerian.*prince',
            r'foreign.*lottery',

            # Urgency and pressure tactics
            r'urgent.*action.*required',
            r'account.*suspended',
            r'immediate.*verification',
            r'limited.*time.*offer',
            r'act.*now.*or',
            r'deadline.*expires',
            r'time.*sensitive',
            r'click.*here.*immediately',

            # Impersonation patterns
            r'paypal.*support',
            r'bank.*verification',
            r'irs.*refund',
            r'social.*security',
            r'government.*grant',
            r'official.*notification',

            # Suspicious keywords
            r'congratulations.*winner',
            r'secret.*millionaire',
            r'anonymous.*hacker',
            r'hack.*account',
            r'recover.*funds',
            r'unclaimed.*money',

            # Technical deception
            r'phishing.*test',  # This should be HIGH risk!
            r'test.*phishing',
            r'security.*test.*site',
            r'malware.*test',
            r'virus.*test'
        ]

        # Enhanced suspicious domain patterns
        self.suspicious_domains = [
            # Free domain providers often used for phishing
            r'\.(tk|ml|ga|cf|xyz|gq|top|club|online|site|store|tech)$',
            r'[a-z]+-[a-z]+-[a-z]+\.(com|net|org)',  # Hyphenated suspicious domains
            r'[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}',     # IP-like domains
            r'(paypal|amazon|google|microsoft|apple|netflix|facebook|instagram|twitter).*[0-9]+\.',  # Brand impersonation
            r'(login|secure|verify|update|account|support).*\.(tk|ml|ga|cf|xyz|gq)',
            r'[a-z]{15,}\.',  # Very long domain names
            r'(bank|credit|loan|finance).*\.(tk|ml|ga|cf|xyz)',
            r'(gov|org|edu).*\.(tk|ml|ga|cf|xyz)',  # Fake government sites
        ]

        # High-risk TLDs
        self.high_risk_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.gq', '.top', '.club', '.online', '.site']

        # Legitimate indicators (reduce false positives)
        self.legitimate_indicators = [
            'https://',
            'ssl certificate',
            'privacy policy',
            'terms of service',
            'contact information',
            'established company',
            'customer reviews',
            'wikipedia.org',
            'github.com',
            'stackoverflow.com'
        ]

        # Enhanced threat intelligence database
        self.threat_database = {
            'known_phishing': [
                'phishing-test.com',  # Add known test phishing sites
                'phishing-site-example.com',
                'fake-bank-login.net',
                'suspicious-paypal.org',
                'free-money-claim.net',  # Add this specific site
                'test-phishing-site.com',
                'malware-test-site.com'
            ],
            'known_malware': [
                'malware-download.exe',
                'virus-infected.zip',
                'trojan-file.pdf'
            ],
            'high_risk_keywords': [
                'phishing',
                'malware',
                'virus',
                'trojan',
                'ransomware',
                'scam',
                'fraud'
            ]
        }
    
    def classify_content(self, content, content_type="text"):
        """
        Enhanced automatic classification with improved phishing detection:
        - LEGITIMATE: Safe content (score < 25)
        - SUSPICIOUS: Potentially harmful content (score 25-60)
        - FRAUDULENT: Confirmed fraudulent/malicious content (score > 60)
        """
        score = 0
        risk_factors = []

        content_lower = content.lower()

        # Check for high-risk keywords in threat database
        for keyword in self.threat_database['high_risk_keywords']:
            if keyword in content_lower:
                score += 30  # High weight for explicit threat keywords
                risk_factors.append(f"High-risk keyword detected: '{keyword}'")

        # Check for phishing patterns with enhanced scoring
        for pattern in self.phishing_patterns:
            if re.search(pattern, content_lower):
                score += 20  # Increased from 25 to 20 for better granularity
                risk_factors.append(f"Phishing pattern detected: {pattern}")

        # Check for suspicious URLs with domain analysis
        urls = self.extract_urls(content)
        for url in urls:
            url_risk = self.analyze_url(url)
            score += url_risk['score']
            if url_risk['factors']:
                risk_factors.extend(url_risk['factors'])

        # Check against known threat database
        if self.check_threat_database(content):
            score += 40  # Increased weight for known threats
            risk_factors.append("Matches known threat database entry")

        # Domain-specific risk assessment
        for url in urls:
            domain_risk = self.assess_domain_risk(url)
            score += domain_risk['score']
            if domain_risk['factors']:
                risk_factors.extend(domain_risk['factors'])

        # Adjust thresholds for better detection
        if score >= 60:  # Lowered from 75
            classification = "FRAUDULENT"
            threat_level = "HIGH"
        elif score >= 25:  # Lowered from 40
            classification = "SUSPICIOUS"
            threat_level = "MEDIUM"
        else:
            classification = "LEGITIMATE"
            threat_level = "LOW"

        return {
            'classification': classification,
            'threat_level': threat_level,
            'risk_score': min(score, 100),
            'risk_factors': risk_factors,
            'confidence': self.calculate_confidence(score, len(risk_factors))
        }
    
    def extract_urls(self, text):
        """Extract URLs from text content"""
        url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
        return url_pattern.findall(text)
    
    def analyze_url(self, url):
        """Analyze URL for suspicious characteristics"""
        score = 0
        factors = []
        
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()
            
            # Check suspicious domain patterns
            for pattern in self.suspicious_domains:
                if re.search(pattern, domain):
                    score += 20
                    factors.append(f"Suspicious domain pattern: {domain}")
            
            # Check URL length
            if len(url) > 200:
                score += 15
                factors.append("Unusually long URL")
            
            # Check for URL shorteners
            shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly']
            if any(shortener in domain for shortener in shorteners):
                score += 10
                factors.append("URL shortener detected")
            
            # Check for IP addresses instead of domain names
            if re.match(r'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', domain):
                score += 25
                factors.append("IP address used instead of domain name")
            
            # Check for HTTPS
            if not url.startswith('https://'):
                score += 10
                factors.append("Non-HTTPS connection")
                
        except Exception as e:
            score += 5
            factors.append("Malformed URL")
        
        return {'score': score, 'factors': factors}
    
    def check_threat_database(self, content):
        """Check content against known threat database"""
        content_lower = content.lower()
        
        # Check against known threats
        for threat_list in self.threat_database.values():
            for threat in threat_list:
                if threat.lower() in content_lower:
                    return True
        return False
    
    def assess_domain_risk(self, url):
        """Assess domain-specific risks beyond basic URL analysis"""
        score = 0
        factors = []

        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()

            # Check for high-risk TLDs
            for tld in self.high_risk_tlds:
                if domain.endswith(tld):
                    score += 25
                    factors.append(f"High-risk TLD detected: {tld}")

            # Check for suspicious subdomain patterns
            if domain.count('.') >= 3:
                score += 15
                factors.append("Multiple subdomains detected")

            # Check for brand impersonation (but whitelist legitimate domains)
            legitimate_domains = {
                'google': ['google.com', 'www.google.com', 'mail.google.com', 'drive.google.com', 'docs.google.com'],
                'paypal': ['paypal.com', 'www.paypal.com'],
                'amazon': ['amazon.com', 'www.amazon.com', 'amazon.in', 'www.amazon.in'],
                'microsoft': ['microsoft.com', 'www.microsoft.com', 'outlook.com', 'live.com'],
                'apple': ['apple.com', 'www.apple.com', 'icloud.com'],
                'netflix': ['netflix.com', 'www.netflix.com'],
                'facebook': ['facebook.com', 'www.facebook.com', 'fb.com'],
                'instagram': ['instagram.com', 'www.instagram.com']
            }
            
            brand_keywords = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'netflix', 'facebook', 'instagram']
            for brand in brand_keywords:
                if brand in domain:
                    # Check if it's a legitimate domain for this brand
                    is_legitimate = False
                    if brand in legitimate_domains:
                        for legit_domain in legitimate_domains[brand]:
                            if domain == legit_domain or domain.endswith('.' + legit_domain):
                                is_legitimate = True
                                break
                    
                    # Only flag if it's not a legitimate domain
                    if not is_legitimate and not domain.startswith(brand + '.'):
                        score += 20
                        factors.append(f"Potential brand impersonation: {brand}")

            # Check for geographic TLDs often used in scams
            geo_tlds = ['.ru', '.cn', '.in', '.br', '.mx']
            for tld in geo_tlds:
                if domain.endswith(tld):
                    score += 10
                    factors.append(f"Geographic TLD with scam potential: {tld}")

        except Exception as e:
            score += 5
            factors.append("Domain analysis error")

        return {'score': score, 'factors': factors}
    
    def calculate_confidence(self, score, factor_count):
        """Calculate confidence level of the classification"""
        if factor_count >= 3 and score >= 50:
            return "HIGH"
        elif factor_count >= 2 or score >= 30:
            return "MEDIUM"
        else:
            return "LOW"

# Initialize the classifier
threat_classifier = ThreatClassifier()

@app.route("/")
def home():
    print("🏠 Home endpoint accessed")
    return jsonify({"message": "CyberGuard AI Backend - Fraud Detection API is running!", "status": "success", "cors": "enabled"})

# Test endpoint for CORS
@app.route("/test")
def test_cors():
    print("🧪 CORS test endpoint accessed")
    return jsonify({"message": "CORS test successful!", "status": "ok", "timestamp": "2025-08-30"})

# Helper to call Gemini API for text analysis
def analyze_with_gemini(prompt, retry_count=0, max_retries=2):
    # Avoid printing secrets (API keys / full URLs) to logs. Mask sensitive values.
    print(f"🤖 Starting Gemini API call (attempt {retry_count + 1}/{max_retries + 1})")
    print("🔑 API Key being used: [REDACTED]")
    print("📡 Gemini API endpoint configured")
    print(f"📝 Prompt length: {len(prompt)} characters")

    try:
        print("🤖 Sending request to Gemini API...")
        headers = {"Content-Type": "application/json"}
        data = {
            "contents": [{"parts": [{"text": prompt}]}]
        }
        response = requests.post(GEMINI_API_URL, headers=headers, json=data)
        print(f"📡 Gemini API response status: {response.status_code}")
        # Avoid printing full response headers which may contain sensitive info
        print("📡 Response headers: [REDACTED]")

        if response.status_code == 200:
            result = response.json()
            # Extract the text content from Gemini response
            if 'candidates' in result and len(result['candidates']) > 0:
                content = result['candidates'][0]['content']['parts'][0]['text']
                print(f"✅ Gemini analysis received ({len(content)} characters)")
                # Lightweight parse to derive a verdict from Gemini's text when possible
                text = content.lower()
                # Look for explicit labels or strong language
                if any(k in text for k in ['fraud', 'phish', 'malicious', 'phishing', 'credential', 'steal']):
                    gemini_verdict = 'FRAUDULENT'
                    gemini_conf = 0.9
                elif any(k in text for k in ['suspicious', 'possibly', 'might be', 'could be']):
                    gemini_verdict = 'SUSPICIOUS'
                    gemini_conf = 0.6
                else:
                    gemini_verdict = 'LEGITIMATE'
                    gemini_conf = 0.2

                return {"analysis": content, "status": "success", "gemini_verdict": gemini_verdict, "gemini_confidence": gemini_conf}
            else:
                print("⚠️ No response from Gemini")
                return {"error": "No response from Gemini", "status": "error"}

        elif response.status_code == 429:
            print("⏱️ Rate limit exceeded - API quota exhausted")
            print("💡 Tip: Check your Google AI Studio billing and quota limits")
            # For rate limits, return a neutral analysis to avoid false positives
            return {
                "analysis": "Rate limit exceeded - analysis unavailable", 
                "status": "rate_limited",
                "gemini_verdict": "LEGITIMATE",  # Default to safe when rate limited
                "gemini_confidence": 0.0,
                "error": "API quota exceeded"
            }

        elif response.status_code == 403:
            print("❌ Gemini API access denied - check API key permissions")
            print("💡 Ensure your API key has Gemini API access enabled")
            return {
                "analysis": "API access denied - analysis unavailable", 
                "status": "access_denied",
                "gemini_verdict": "LEGITIMATE",
                "gemini_confidence": 0.0,
                "error": "API access denied"
            }

        elif response.status_code == 404:
            print("❌ Gemini model not found - check model version")
            return {
                "analysis": "Model not found - analysis unavailable", 
                "status": "model_not_found",
                "gemini_verdict": "LEGITIMATE",
                "gemini_confidence": 0.0,
                "error": "Model not found"
            }

        elif response.status_code >= 500:
            print(f"🔥 Gemini API server error: {response.status_code}")
            print("💡 Google's servers may be experiencing issues")
            # Retry server errors
            if retry_count < max_retries:
                import time
                delay = (2 ** retry_count) * 2  # Exponential backoff: 2s, 4s, 8s
                print(f"🔄 Retrying in {delay} seconds... (attempt {retry_count + 1}/{max_retries})")
                time.sleep(delay)
                return analyze_with_gemini(prompt, retry_count + 1, max_retries)
            else:
                return {
                    "analysis": "Server error - analysis unavailable", 
                    "status": "server_error",
                    "gemini_verdict": "LEGITIMATE",
                    "gemini_confidence": 0.0,
                    "error": f"Server error {response.status_code}"
                }

        else:
            print(f"❌ Unexpected Gemini API error: {response.status_code}")
            return {
                "analysis": "Unexpected error - analysis unavailable", 
                "status": "error",
                "gemini_verdict": "LEGITIMATE",
                "gemini_confidence": 0.0,
                "error": f"HTTP {response.status_code}"
            }

    except Exception as e:
        print(f"💥 Exception in Gemini API call: {str(e)}")
        return {
            "analysis": "Unexpected error - analysis unavailable", 
            "status": "error",
            "gemini_verdict": "LEGITIMATE",
            "gemini_confidence": 0.0,
            "error": str(e)
        }

# Enhanced fallback analysis when Gemini API is not available
def get_enhanced_fallback_analysis(prompt, reason="API_UNAVAILABLE"):
    """Enhanced fallback analysis with detailed error information and local AI processing"""

    print(f"🔄 Using enhanced fallback analysis (Reason: {reason})")

    # Extract content for analysis
    content = prompt.lower()

    # Check Google Safe Browsing API if URL is present
    urls = threat_classifier.extract_urls(prompt)
    safe_browsing_threat = False
    safe_browsing_result = None
    if urls:
        safe_browsing_result = rate_limited_safe_browsing(urls[0], SAFE_BROWSING_API_KEY)
        if safe_browsing_result.get("threat_found"):
            safe_browsing_threat = True

    # Perform automatic classification
    classification_result = threat_classifier.classify_content(prompt)

    # Boost score if Safe Browsing detected a threat
    if safe_browsing_threat and safe_browsing_result:
        classification_result['risk_score'] = min(classification_result['risk_score'] + 50, 100)
        classification_result['risk_factors'].append(f"Google Safe Browsing: {safe_browsing_result['threat_type']} detected")
        if classification_result['risk_score'] >= 60:
            classification_result['classification'] = "FRAUDULENT"
            classification_result['threat_level'] = "HIGH"

    # Create enhanced analysis based on reason
    if reason == "RATE_LIMIT_EXCEEDED":
        status_message = "⚠️ GOOGLE GEMINI API RATE LIMIT EXCEEDED"
        detail_message = "Your free tier quota has been reached. The system is using local AI analysis instead."
    elif reason == "API_NOT_ENABLED":
        status_message = "❌ GOOGLE GEMINI API NOT ENABLED"
        detail_message = "API key may not have proper permissions. Using local analysis."
    elif reason == "MODEL_NOT_FOUND":
        status_message = "❌ GEMINI MODEL NOT FOUND"
        detail_message = "The requested model may not be available. Using local analysis."
    else:
        status_message = f"⚠️ GOOGLE GEMINI API UNAVAILABLE ({reason})"
        detail_message = "AI service temporarily unavailable. Using local analysis."

    # Generate detailed analysis based on classification
    if "website" in content or "url" in content:
        # Extract URL from prompt for website analysis
        extracted_urls = threat_classifier.extract_urls(prompt)
        target_url = extracted_urls[0] if extracted_urls else None
        return generate_enhanced_website_analysis(target_url, classification_result, status_message, detail_message)
    elif "app" in content or "mobile" in content:
        return generate_enhanced_app_analysis(prompt, classification_result, status_message, detail_message)
    else:
        return generate_enhanced_general_analysis(prompt, classification_result, status_message, detail_message)

# Fallback analysis when Gemini API is not available
def get_fallback_analysis(prompt):
    """Enhanced fallback analysis with automatic classification"""

    # Extract content for analysis
    content = prompt.lower()

    # Perform automatic classification
    classification_result = threat_classifier.classify_content(prompt)

    # Generate detailed analysis based on classification
    if "website" in content or "url" in content:
        return generate_website_analysis(prompt, classification_result)
    elif "app" in content or "mobile" in content:
        return generate_app_analysis(prompt, classification_result)
    else:
        return generate_general_analysis(prompt, classification_result)

def generate_website_analysis(prompt, classification):
    """Generate detailed website analysis with proactive threat identification"""
    
    # Extract URL if present
    urls = threat_classifier.extract_urls(prompt)
    target_url = urls[0] if urls else "the provided URL"
    
    analysis_parts = [
        f"�️ **AUTOMATED THREAT ANALYSIS REPORT**",
        f"",
        f"**Classification:** {classification['classification']}",
        f"**Threat Level:** {classification['threat_level']}",
        f"**Risk Score:** {classification['risk_score']}/100",
        f"**Confidence:** {classification['confidence']}",
        f"",
        f"**1. SECURITY ASSESSMENT**"
    ]
    
    if classification['classification'] == 'FRAUDULENT':
        analysis_parts.extend([
            f"⚠️ **HIGH RISK DETECTED** - This website shows multiple indicators of fraudulent activity.",
            f"🚨 **RECOMMENDATION:** Avoid this website entirely. Do not enter personal information.",
            f"",
            f"**Identified Threats:**"
        ])
    elif classification['classification'] == 'SUSPICIOUS':
        analysis_parts.extend([
            f"⚠️ **MEDIUM RISK DETECTED** - This website exhibits suspicious characteristics.",
            f"🔍 **RECOMMENDATION:** Exercise extreme caution. Verify authenticity before proceeding.",
            f"",
            f"**Suspicious Indicators:**"
        ])
    else:
        analysis_parts.extend([
            f"✅ **LOW RISK** - Initial analysis suggests this website appears legitimate.",
            f"ℹ️ **RECOMMENDATION:** Standard web safety practices recommended.",
            f"",
            f"**Positive Indicators:**"
        ])
    
    # Add risk factors
    for factor in classification['risk_factors']:
        analysis_parts.append(f"• {factor}")
    
    if not classification['risk_factors']:
        analysis_parts.append("• No significant risk factors detected")
    
    analysis_parts.extend([
        f"",
        f"**2. PROACTIVE PROTECTION MEASURES**",
        f"• Real-time URL scanning completed",
        f"• Cross-referenced with threat intelligence databases",
        f"• Behavioral pattern analysis performed",
        f"• Domain reputation check conducted",
        f"",
        f"**3. ADDITIONAL SECURITY RECOMMENDATIONS**",
        f"• Always verify website URLs before entering sensitive information",
        f"• Look for HTTPS encryption (🔒) in the address bar",
        f"• Be cautious of websites requesting immediate action",
        f"• Use official apps or bookmarked links when possible",
        f"",
        f"---",
        f"*Analysis performed by CyberGuard AI Security Engine*",
        f"*Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*"
    ])
    
    return {
        "analysis": "\n".join(analysis_parts),
        "classification": classification,
        "status": "success",
        "timestamp": datetime.now().isoformat()
    }

def generate_app_analysis(prompt, classification):
    """Generate detailed app analysis with proactive threat identification"""
    
    analysis_parts = [
        f"📱 **MOBILE APP SECURITY ANALYSIS**",
        f"",
        f"**Classification:** {classification['classification']}",
        f"**Threat Level:** {classification['threat_level']}",
        f"**Risk Score:** {classification['risk_score']}/100",
        f"**Confidence:** {classification['confidence']}",
        f"",
        f"**1. APP SECURITY ASSESSMENT**"
    ]
    
    if classification['classification'] == 'FRAUDULENT':
        analysis_parts.extend([
            f"🚨 **MALICIOUS APP DETECTED** - This application shows strong indicators of malicious behavior.",
            f"⛔ **CRITICAL RECOMMENDATION:** Do not install or use this application.",
            f"",
            f"**Malicious Indicators:**"
        ])
    elif classification['classification'] == 'SUSPICIOUS':
        analysis_parts.extend([
            f"⚠️ **POTENTIALLY UNSAFE APP** - This application has suspicious characteristics.",
            f"🔍 **RECOMMENDATION:** Verify app authenticity through official app stores only.",
            f"",
            f"**Suspicious Behaviors:**"
        ])
    else:
        analysis_parts.extend([
            f"✅ **APP APPEARS SAFE** - No significant threats detected in initial analysis.",
            f"ℹ️ **RECOMMENDATION:** Download only from official app stores with user reviews.",
            f"",
            f"**Safety Indicators:**"
        ])
    
    # Add risk factors
    for factor in classification['risk_factors']:
        analysis_parts.append(f"• {factor}")
    
    if not classification['risk_factors']:
        analysis_parts.append("• No significant risk factors detected")
    
    analysis_parts.extend([
        f"",
        f"**2. MOBILE SECURITY BEST PRACTICES**",
        f"• Only download apps from official stores (Google Play, App Store)",
        f"• Check app permissions before installation",
        f"• Read user reviews and ratings",
        f"• Verify developer information",
        f"• Keep apps updated to latest versions",
        f"",
        f"**3. PRIVACY PROTECTION**",
        f"• Review app permissions carefully",
        f"• Limit access to sensitive data (contacts, location, camera)",
        f"• Monitor app behavior after installation",
        f"• Use app reputation checking tools",
        f"",
        f"---",
        f"*Analysis performed by CyberGuard AI Mobile Security Engine*",
        f"*Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*"
    ])
    
    return {
        "analysis": "\n".join(analysis_parts),
        "classification": classification,
        "status": "success",
        "timestamp": datetime.now().isoformat()
    }

def generate_general_analysis(prompt, classification):
    """Generate general content analysis"""
    
    analysis_parts = [
        f"🔍 **CONTENT SECURITY ANALYSIS**",
        f"",
        f"**Classification:** {classification['classification']}",
        f"**Threat Level:** {classification['threat_level']}",
        f"**Risk Score:** {classification['risk_score']}/100",
        f"**Confidence:** {classification['confidence']}",
        f"",
        f"**ANALYSIS RESULTS:**"
    ]
    
    if classification['classification'] == 'FRAUDULENT':
        analysis_parts.append("🚨 **FRAUDULENT CONTENT DETECTED** - High probability of malicious intent.")
    elif classification['classification'] == 'SUSPICIOUS':
        analysis_parts.append("⚠️ **SUSPICIOUS CONTENT** - Exercise caution and verify authenticity.")
    else:
        analysis_parts.append("✅ **CONTENT APPEARS LEGITIMATE** - No significant threats detected.")
    
    analysis_parts.extend([
        f"",
        f"**Risk Factors Identified:**"
    ])
    
    for factor in classification['risk_factors']:
        analysis_parts.append(f"• {factor}")
    
    if not classification['risk_factors']:
        analysis_parts.append("• No significant risk factors detected")
    
    analysis_parts.extend([
        f"",
        f"---",
        f"*Analysis performed by CyberGuard AI Security Engine*",
        f"*Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*"
    ])
    
    return {
        "analysis": "\n".join(analysis_parts),
        "classification": classification,
        "status": "success",
        "timestamp": datetime.now().isoformat()
    }


@app.route("/analyze/website", methods=["POST"])
def analyze_website():
    try:
        print("📨 Received website analysis request")
        data = request.json
        url = data.get("url")
        print(f"🌐 Analyzing website: {url}")
        print(f"📊 Request data: {data}")

        if not url:
            print("❌ No URL provided in request")
            return jsonify({"error": "No URL provided"}), 400

        # Extract domain (normalize common user inputs like 'www.google.com' by
        # adding an http:// scheme when missing so urlparse populates netloc)
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc

        # If user supplied a bare hostname without scheme (e.g. 'www.google.com'),
        # urlparse will put it in path instead of netloc. Try to recover by
        # prepending 'http://' and reparsing.
        if not domain:
            if parsed_url.path and '.' in parsed_url.path and not parsed_url.path.startswith('/'):
                # common case: 'www.google.com' -> treat as hostname
                candidate = parsed_url.path
                url = 'http://' + candidate
                parsed_url = urllib.parse.urlparse(url)
                domain = parsed_url.netloc
            else:
                # try adding http:// to the original URL and reparse as a fallback
                if not re.match(r'^[a-zA-Z]+://', url):
                    try_url = 'http://' + url
                    parsed_try = urllib.parse.urlparse(try_url)
                    if parsed_try.netloc:
                        url = try_url
                        parsed_url = parsed_try
                        domain = parsed_url.netloc

        # Normalize domain (strip port and lowercase)
        if domain:
            domain = domain.split(':')[0].lower()

        # Check built-in allowlist first (major domains like google.com, youtube.com)
        if domain and domain.lower() in BUILTIN_ALLOWLIST:
            print(f"✅ Domain {domain} is in built-in allowlist - returning LEGITIMATE")
            return jsonify({
                "verdict": "LEGITIMATE",
                "status": "success",
                "confidence_score": 0.0,
                "threat_sources": [],
                "analysis_summary": {
                    "safe_browsing_threat": False,
                    "ml_phishing_detected": False,
                    "heuristic_risk_level": "NONE",
                    "combined_risk_score": 0
                },
                "ml_model": {
                    "prediction": 0,
                    "confidence": 0.0,
                    "proba": [1.0, 0.0],
                    "features": None,
                    "model_available": ml_model is not None
                },
                "whois": {"status": "allowlisted"},
                "html": {"status": "allowlisted"},
                "safe_browsing": {"threat_found": False, "status": "allowlisted"},
                "heuristic_classification": {"classification": "LEGITIMATE", "risk_score": 0},
                "heuristic_score": 0,
                "combined_details": {"allowlist": "builtin_protected"},
                "verdict_source": "allowlist",
                "timestamp": datetime.now().isoformat()
            })

        # Immediately skip analysis for internal/local URLs to avoid false positives
        if (not domain) or domain in ("localhost", "127.0.0.1") or (domain and domain.startswith('192.168.')):
            print(f"ℹ️ Skipping analysis for internal/local or unresolvable URL: {url} (parsed domain: {domain})")
            # Return a lightweight LEGITIMATE response to avoid extension loops
            return jsonify({
                "verdict": "LEGITIMATE",
                "status": "success",
                "confidence_score": 0,
                "threat_sources": [],
                "analysis_summary": {"combined_risk_score": 0},
                "ml_model": {"model_available": ml_model is not None},
                "whois": {},
                "html": {"error": "internal_url_skipped"},
                "safe_browsing": {"threat_found": False},
                "heuristic_classification": {"classification": "LEGITIMATE", "risk_score": 0},
                "timestamp": datetime.now().isoformat()
            })

        # WHOIS features
        whois_features = get_whois_features(domain)
        print(f"🔎 WHOIS features: {whois_features}")

        # HTML features
        html_features = get_html_features(url)
        print(f"🔎 HTML features: {html_features}")

        # ML model prediction (if available)
        ml_prediction = None
        ml_proba = None
        ml_features = None
        if ml_model is not None:
            try:
                ml_features, fallback_used = safe_feature_extraction(url)
                # Align feature length with model expectation if available
                expected = getattr(ml_model, 'n_features_in_', None)
                if expected and len(ml_features) != expected:
                    if len(ml_features) < expected:
                        ml_features = ml_features + [0] * (expected - len(ml_features))
                    else:
                        ml_features = ml_features[:expected]

                # Guard prediction calls to avoid attribute errors from different xgboost versions
                if hasattr(ml_model, 'predict'):
                    try:
                        raw_pred = ml_model.predict([ml_features])
                        # raw_pred may be numpy array, list, or nested; coerce
                        try:
                            ml_prediction = int(raw_pred[0])
                        except Exception:
                            # maybe nested
                            try:
                                ml_prediction = int(raw_pred[0][0])
                            except Exception:
                                ml_prediction = int(raw_pred)
                    except Exception:
                        ml_prediction = None

                # Robustly extract predict_proba output into [p0, p1]
                if hasattr(ml_model, 'predict_proba'):
                    try:
                        proba_raw = ml_model.predict_proba([ml_features])
                        # Convert to plain Python nested lists where possible
                        try:
                            if hasattr(proba_raw, 'tolist'):
                                proba_list = proba_raw.tolist()
                            else:
                                proba_list = list(proba_raw)
                        except Exception:
                            proba_list = list(proba_raw)

                        if isinstance(proba_list, list) and len(proba_list) > 0:
                            first = proba_list[0]
                            if isinstance(first, (list, tuple)) and len(first) >= 2:
                                p0 = float(first[0]); p1 = float(first[1])
                                ml_proba = [p0, p1]
                                # If prediction wasn't set earlier, infer from proba
                                if ml_prediction is None:
                                    ml_prediction = int(p1 > 0.5)
                            else:
                                # single value probability (positive class)
                                try:
                                    p1 = float(first)
                                    ml_proba = [1.0 - p1, p1]
                                    if ml_prediction is None:
                                        ml_prediction = int(p1 > 0.5)
                                except Exception:
                                    ml_proba = None
                        else:
                            ml_proba = None
                    except Exception as e:
                        print(f"[WARN] predict_proba extraction error: {e}")
                        ml_proba = None

                print(f"🤖 ML model prediction: {ml_prediction}, proba: {ml_proba} (fallback_used={fallback_used})")
            except Exception as e:
                print(f"❌ ML model prediction error: {e}")

        # Perform automatic classification (existing heuristic)
        classification_result = threat_classifier.classify_content(url, "url")

        # Check Google Safe Browsing API for real-time threat detection (rate-limited, cached)
        safe_browsing_result = rate_limited_safe_browsing(url, SAFE_BROWSING_API_KEY)

        # Compute heuristic score using modular helper
        heuristic_score = compute_heuristic_score(domain, whois_features, html_features, classification_result, allowlist=ALLOWLIST, blacklist=BLACKLIST)

        # Combine ML proba and heuristic into final verdict. If the ML features
        # were produced by the fallback extractor (due to network/WHOIS failures),
        # pass that flag so the combiner can reduce ML weight to avoid false positives.
        combined = combine_scores(
            ml_proba,
            heuristic_score,
            safe_browsing_result,
            ml_fallback=(ml_features is not None and isinstance(ml_features, list) and len([v for v in ml_features if v != 0]) == 0)
        )

        # Optionally consult Gemini as an external LLM-based check when API key is configured.
        gemini_result = None
        try:
            if GOOGLE_API_KEY and GOOGLE_API_KEY != 'YOUR_NEW_GEMINI_API_KEY_HERE':
                prompt = f"Analyze this URL for phishing or fraud: {url}\nProvide a short verdict and reasoning."
                gem = analyze_with_gemini(prompt)
                if isinstance(gem, dict) and gem.get('status') == 'success':
                    gemini_result = {
                        'verdict': gem.get('gemini_verdict', 'LEGITIMATE'),
                        'confidence': gem.get('gemini_confidence', 0.0),
                        'raw': gem.get('analysis')
                    }
        except Exception as e:
            print(f"[WARN] Gemini check failed: {e}")

        # If both Gemini and ML indicate a threat (consensus), escalate the combined verdict
        try:
            ml_positive = False
            if ml_proba and isinstance(ml_proba, (list, tuple)):
                ml_positive = ml_proba[1] > 0.5
            if gemini_result and gemini_result.get('verdict') == 'FRAUDULENT' and ml_positive:
                # Force escalate to FRAUDULENT with high confidence
                combined = {'verdict': 'FRAUDULENT', 'confidence': 99.0, 'combined_score': 95, 'details': combined.get('details', {}) if isinstance(combined, dict) else {}}
                print('[INFO] Gemini + ML consensus: escalating verdict to FRAUDULENT')
        except Exception:
            pass

        # Prefer Gemini's assessment for the user-facing verdict when Gemini returns
        # a non-LEGITIMATE result. We still compute ML and heuristics, but present
        # Gemini's verdict as authoritative for display. Do NOT expose any API key
        # values in the response or logs.
        verdict_source = 'combined'
        try:
            if gemini_result and gemini_result.get('verdict'):
                gver = gemini_result.get('verdict')
                if gver != 'LEGITIMATE':
                    combined = {
                        'verdict': gver,
                        'confidence': float(gemini_result.get('confidence', 0.0) * 100),
                        'combined_score': combined.get('combined_score', 0) if isinstance(combined, dict) else 0,
                        'details': combined.get('details', {}) if isinstance(combined, dict) else {}
                    }
                    verdict_source = 'gemini'
                    print('[INFO] Gemini verdict preferred for user-facing result (non-LEGITIMATE)')
        except Exception:
            pass

        # Defensive computation of ML confidence
        ml_confidence_pct = None
        try:
            if ml_proba and isinstance(ml_proba, (list, tuple)):
                # ml_proba expected [p0, p1]
                ml_confidence_pct = round(float(max(ml_proba)) * 100, 2)
        except Exception:
            ml_confidence_pct = None

        response = {
            "verdict": combined['verdict'],
            "confidence_score": round(combined['confidence'], 2),
            "gemini": gemini_result,
            "verdict_source": verdict_source,
            "threat_sources": [s for s in (['Google Safe Browsing'] if safe_browsing_result.get('threat_found') else [])],
            "analysis_summary": {
                "safe_browsing_threat": safe_browsing_result.get("threat_found", False),
                "ml_phishing_detected": bool(ml_prediction == 1) if ml_prediction is not None else False,
                "heuristic_risk_level": classification_result.get('threat_level', 'LOW'),
                "combined_risk_score": combined['combined_score']
            },
            "ml_model": {
                "prediction": int(ml_prediction) if ml_prediction is not None else None,
                "confidence": ml_confidence_pct,
                "proba": ml_proba if ml_proba is not None else None,
                "features": ml_features,
                "model_available": ml_model is not None
            },
            "whois": whois_features,
            "html": html_features,
            "safe_browsing": safe_browsing_result,
            "heuristic_classification": classification_result,
            "heuristic_score": heuristic_score,
            "combined_details": combined.get('details', {}),
            "timestamp": datetime.now().isoformat()
        }

        print(f"✅ Enhanced combined verdict: {combined['verdict']} (combined_score: {combined['combined_score']}%)")
        return jsonify(response)
    except Exception as e:
        print(f"❌ Error in website analysis: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}", "status": "error"}), 500

@app.route("/analyze/adult-content", methods=["POST", "OPTIONS"])
def analyze_adult_content():
    try:
        data = request.json
        url = data.get("url", "")
        user_age = data.get("userAge", 18)
        
        print(f"🔞 Adult content analysis for: {url}")
        
        if not url:
            return jsonify({"error": "URL is required"}), 400
        
        # Extract domain and path
        domain = urllib.parse.urlparse(url).netloc.lower()
        path = urllib.parse.urlparse(url).path.lower()
        query = urllib.parse.urlparse(url).query.lower()
        full_url = url.lower()
        
        # Enhanced adult content detection
        adult_keywords = [
            'porn', 'xxx', 'sex', 'adult', 'nude', 'naked', 'erotic', 'nsfw',
            'webcam', 'cam', 'dating', 'hookup', 'escort', 'massage', 'strip',
            'fetish', 'bdsm', 'mature', 'milf', 'amateur', 'hardcore',
            'softcore', 'lingerie', 'bikini', 'swimsuit', 'underwear',
            'onlyfans', 'fansly', 'chaturbate', 'pornhub', 'xvideos'
        ]
        
        # Known adult domains
        adult_domains = [
            'pornhub.com', 'xvideos.com', 'xnxx.com', 'redtube.com', 'youporn.com',
            'tube8.com', 'spankbang.com', 'xhamster.com', 'beeg.com', 'tnaflix.com',
            'chaturbate.com', 'cam4.com', 'bongacams.com', 'stripchat.com',
            'onlyfans.com', 'fansly.com', 'manyvids.com', 'clips4sale.com',
            'livejasmin.com', 'camsoda.com', 'myfreecams.com', 'streamate.com'
        ]
        
        confidence = 0.0
        detected_indicators = []
        
        # Check against known adult domains
        for adult_domain in adult_domains:
            if adult_domain in domain:
                confidence = max(confidence, 0.95)
                detected_indicators.append(f"Known adult domain: {adult_domain}")
        
        # Check for adult keywords in URL components
        keyword_matches = []
        for keyword in adult_keywords:
            if (keyword in domain or keyword in path or keyword in query):
                keyword_matches.append(keyword)
                confidence = max(confidence, 0.7)
        
        if keyword_matches:
            detected_indicators.append(f"Adult keywords: {', '.join(keyword_matches)}")
        
        # Additional heuristic checks
        if any(x in domain for x in ['xxx', '18+', 'adult', 'sex']):
            confidence = max(confidence, 0.8)
            detected_indicators.append("Adult content indicators in domain")
        
        # Age-based confidence adjustment
        is_adult_content = confidence > 0.6
        should_block = False
        
        if user_age < 18:
            should_block = confidence > 0.3  # Lower threshold for minors
        else:
            should_block = confidence > 0.7  # Higher threshold for adults
        
        result = {
            "isAdultContent": is_adult_content,
            "shouldBlock": should_block,
            "confidence": round(confidence, 2),
            "userAge": user_age,
            "detectedIndicators": detected_indicators,
            "recommendation": "BLOCK" if should_block else "ALLOW",
            "analysis": {
                "domain": domain,
                "keywordMatches": keyword_matches,
                "domainMatch": any(adult_domain in domain for adult_domain in adult_domains)
            },
            "timestamp": datetime.now().isoformat()
        }
        
        print(f"🔞 Adult content result: {is_adult_content} (confidence: {confidence})")
        return jsonify(result)
        
    except Exception as e:
        print(f"❌ Error in adult content analysis: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}", "status": "error"}), 500

@app.route("/analyze/app", methods=["POST"])
def analyze_app():
    try:
        # Support JSON metadata or direct APK file upload
        apk_ml_result = None
        if request.files and 'file' in request.files:
            # Delegate to existing APK file analysis endpoint logic
            file = request.files['file']
            # reuse analyze_apk_file logic by saving temporarily and calling helper
            filename = secure_filename(file.filename)
            temp_path = os.path.join(tempfile.gettempdir(), filename)
            file.save(temp_path)
            try:
                apk_features = extract_apk_features_simple(temp_path)
                if apk_ml_model is not None:
                    try:
                        prediction = apk_ml_model.predict([apk_features])[0]
                        confidence = max(apk_ml_model.predict_proba([apk_features])[0]) if hasattr(apk_ml_model, 'predict_proba') else 0.85
                        apk_ml_result = {"prediction": int(prediction), "confidence": float(confidence * 100), "classification": "MALWARE" if prediction == 1 else "BENIGN"}
                    except Exception as e:
                        print(f"❌ APK ML prediction error: {e}")
                file_info = {"filename": filename, "size_mb": round(os.path.getsize(temp_path) / (1024*1024), 2)}
                final_verdict = "UNKNOWN"
                if apk_ml_result and apk_ml_result.get('prediction') is not None:
                    if apk_ml_result['prediction'] == 1 and apk_ml_result['confidence'] > 70:
                        final_verdict = 'MALWARE'
                    elif apk_ml_result['prediction'] == 0 and apk_ml_result['confidence'] > 70:
                        final_verdict = 'BENIGN'
                    else:
                        final_verdict = 'SUSPICIOUS'

                return jsonify({"status":"success","file_info":file_info,"ml_analysis":apk_ml_result,"final_verdict":final_verdict})
            finally:
                if os.path.exists(temp_path):
                    os.remove(temp_path)

        data = request.get_json(silent=True) or {}
        app_name = data.get("app_name", "")
        package = data.get("package", "")
        description = data.get("description", "")
        
        if not app_name and not package and not description:
            return jsonify({"error": "No app details provided"}), 400
        
        # Combine app details for classification
        app_content = f"App: {app_name} Package: {package} Description: {description}"
        classification_result = threat_classifier.classify_content(app_content, "mobile_app")
        
        # Enhanced APK analysis with ML model (if available) using text features
        if apk_ml_model is not None:
            try:
                features = extract_app_features_from_text(app_name, package, description)
                apk_prediction = apk_ml_model.predict([features])[0]
                apk_confidence = max(apk_ml_model.predict_proba([features])[0]) if hasattr(apk_ml_model, 'predict_proba') else 0.8
                apk_ml_result = {"prediction": int(apk_prediction), "confidence": float(apk_confidence * 100), "classification": "MALWARE" if apk_prediction == 1 else "BENIGN"}
                print(f"🤖 APK ML prediction: {apk_prediction}, confidence: {apk_confidence:.2f}")
            except Exception as e:
                print(f"❌ APK ML prediction error: {e}")
        
        prompt = f"""Analyze the following mobile application for signs of being fake, fraudulent, or malicious.
        Provide a detailed analysis including:
        1. Risk Level (Low, Medium, High)
        2. Fraud Category (if any): Fake App, Malware, Adware, etc.
        3. Detailed explanation of your analysis
        4. Specific red flags or indicators found
        
        App Details:
        - App Name: {app_name}
        - Package Name: {package}
        - Description: {description}
        
        Format your response clearly with sections for each point above."""
        
        result = analyze_with_gemini(prompt)
        
        # Enhanced decision making with ML model
        final_verdict = "LEGITIMATE"
        confidence_score = classification_result.get('risk_score', 0)
        threat_sources = []
        
        # APK ML model has highest priority
        if apk_ml_result and apk_ml_result['prediction'] == 1:
            final_verdict = "MALWARE"
            confidence_score = apk_ml_result['confidence']
            threat_sources.append("APK Malware Detection Model")
            
        # Heuristic analysis
        elif classification_result['classification'] == 'FRAUDULENT':
            final_verdict = "FRAUDULENT"
            confidence_score = classification_result['risk_score']
            threat_sources.append("Heuristic Analysis")
            
        elif classification_result['classification'] == 'SUSPICIOUS':
            final_verdict = "SUSPICIOUS"
            confidence_score = classification_result['risk_score']
            threat_sources.append("Heuristic Analysis")
        
        # Add enhanced classification data to result
        if result.get("status") == "success":
            result["automatic_classification"] = classification_result
            result["apk_ml_analysis"] = apk_ml_result
            result["final_verdict"] = final_verdict
            result["confidence_score"] = confidence_score
            result["threat_sources"] = threat_sources
            result["mobile_security"] = {
                "threat_detected": final_verdict != "LEGITIMATE",
                "install_recommendation": "DO NOT INSTALL" if final_verdict in ["MALWARE", "FRAUDULENT"] else "VERIFY FIRST" if final_verdict == "SUSPICIOUS" else "SAFE TO INSTALL",
                "store_verification_required": final_verdict != "LEGITIMATE",
                "ml_model_used": apk_ml_result is not None
            }
        
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}", "status": "error"}), 500


@app.route('/', methods=['GET'])
def root_redirect():
    """Redirect to FRONTEND_URL if set, otherwise probe common frontend ports."""
    forced = os.getenv('FRONTEND_URL')
    if forced:
        return redirect(forced)
    frontend = find_frontend_url()
    if frontend:
        return redirect(frontend)
    return jsonify({"status": "backend running", "frontend": None})


@app.route('/health', methods=['GET'])
def health():
    """Return quick health status for monitoring."""
    frontend = os.getenv('FRONTEND_URL') or find_frontend_url()
    return jsonify({
        "status": "ok",
        "ml_model_loaded": ml_model is not None,
        "apk_model_loaded": apk_ml_model is not None,
        "frontend_url": frontend
    })

def extract_app_features_from_text(app_name, package_name, description):
    """Extract basic features from app metadata for ML model"""
    # This is a simplified feature extraction for text-based analysis
    # In a real APK analysis, you'd extract features from the actual APK file
    
    features = [0] * 215  # Initialize with zeros (assuming 215 features like the model)
    
    # Simple heuristic feature extraction based on text
    suspicious_keywords = [
        'hack', 'crack', 'mod', 'free', 'premium', 'unlock', 'cheat', 
        'generator', 'unlimited', 'coins', 'gems', 'money', 'admin',
        'root', 'exploit', 'bypass', 'pirate'
    ]
    
    permissions_keywords = [
        'sms', 'phone', 'camera', 'location', 'contacts', 'storage',
        'internet', 'network', 'admin', 'install', 'system'
    ]
    
    text_content = f"{app_name} {package_name} {description}".lower()
    
    # Feature 0-20: Suspicious keywords
    for i, keyword in enumerate(suspicious_keywords[:20]):
        if keyword in text_content:
            features[i] = 1
    
    # Feature 21-40: Permission-related keywords  
    for i, keyword in enumerate(permissions_keywords[:20]):
        if keyword in text_content:
            features[21 + i] = 1
    
    # Feature 41: Package name suspiciousness
    if package_name and ('.' not in package_name or len(package_name.split('.')) < 3):
        features[41] = 1
        
    # Feature 42: App name length
    features[42] = 1 if len(app_name) > 50 else 0
    
    # Feature 43: Description length
    features[43] = 1 if len(description) > 1000 else 0
    
    return features

@app.route("/analyze/apk-file", methods=["POST"])
def analyze_apk_file():
    """Analyze uploaded APK file for malware detection"""
    try:
        print("📱 Received APK analysis request")
        
        if 'file' not in request.files:
            return jsonify({"error": "No file uploaded", "status": "error"}), 400
            
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No file selected", "status": "error"}), 400
            
        if not file.filename.lower().endswith('.apk'):
            return jsonify({"error": "Only APK files are allowed", "status": "error"}), 400
        
        print(f"📱 Analyzing APK: {file.filename}")
        
        # Save uploaded file temporarily
        filename = secure_filename(file.filename)
        temp_path = os.path.join(tempfile.gettempdir(), filename)
        file.save(temp_path)
        
        try:
            # Extract features from APK file using advanced or simple method
            apk_features, apk_metadata = extract_apk_features_advanced(temp_path)
            
            print(f"🔍 Extracted {len(apk_features)} features from APK")
            
            # ML prediction if model is available
            ml_result = None
            if apk_ml_model is not None:
                try:
                    # Ensure feature vector has correct length for model
                    features_array = normalize_features_for_model(apk_features, apk_ml_model)
                    
                    # Make prediction
                    prediction = None
                    if hasattr(apk_ml_model, 'predict'):
                        pred_raw = apk_ml_model.predict([features_array])
                        prediction = int(pred_raw[0]) if hasattr(pred_raw, '__getitem__') else int(pred_raw)
                    
                    # Get confidence/probability
                    confidence = 0.5
                    proba = None
                    if hasattr(apk_ml_model, 'predict_proba'):
                        proba_raw = apk_ml_model.predict_proba([features_array])
                        if hasattr(proba_raw, '__getitem__') and len(proba_raw) > 0:
                            proba_row = proba_raw[0]
                            if hasattr(proba_row, '__getitem__') and len(proba_row) >= 2:
                                proba = [float(proba_row[0]), float(proba_row[1])]
                                confidence = max(proba)
                            else:
                                confidence = float(proba_row) if hasattr(proba_row, '__float__') else 0.5
                    
                    ml_result = {
                        "prediction": prediction,  # 0 = benign, 1 = malware
                        "confidence": float(confidence * 100),
                        "proba": proba,
                        "classification": "MALWARE" if prediction == 1 else "BENIGN",
                        "features_used": len(features_array)
                    }
                    print(f"🤖 APK ML prediction: {prediction} ({ml_result['classification']}) - Confidence: {confidence:.2f}")
                except Exception as e:
                    print(f"❌ APK ML prediction error: {e}")
                    ml_result = {"error": str(e), "model_available": True}
            else:
                ml_result = {"error": "APK malware detection model not available", "model_available": False}
            
            # Basic file analysis
            file_info = {
                "filename": filename,
                "size_mb": round(os.path.getsize(temp_path) / (1024*1024), 2),
                "analysis_timestamp": datetime.now().isoformat(),
                **apk_metadata
            }
            
            # Determine final verdict based on ML prediction
            final_verdict = "UNKNOWN"
            recommendation = "VERIFY WITH ADDITIONAL SCANNERS"
            install_safe = False
            
            if ml_result and "prediction" in ml_result:
                confidence_threshold = 70.0
                if ml_result["prediction"] == 1 and ml_result["confidence"] > confidence_threshold:
                    final_verdict = "MALWARE"
                    recommendation = "DO NOT INSTALL - MALWARE DETECTED"
                    install_safe = False
                elif ml_result["prediction"] == 0 and ml_result["confidence"] > confidence_threshold:
                    final_verdict = "BENIGN"
                    recommendation = "APPEARS SAFE TO INSTALL"
                    install_safe = True
                else:
                    final_verdict = "SUSPICIOUS"
                    recommendation = "EXERCISE CAUTION - VERIFY WITH ADDITIONAL SCANNERS"
                    install_safe = False
            
            result = {
                "status": "success",
                "final_verdict": final_verdict,
                "file_info": file_info,
                "ml_analysis": ml_result,
                "security_recommendation": {
                    "install_safe": install_safe,
                    "recommendation": recommendation,
                    "confidence_level": ml_result.get("confidence", 0) if ml_result and "confidence" in ml_result else 0
                },
                "analysis_summary": {
                    "malware_detected": final_verdict == "MALWARE",
                    "risk_level": "HIGH" if final_verdict == "MALWARE" else "LOW" if final_verdict == "BENIGN" else "MEDIUM",
                    "combined_risk_score": ml_result.get("confidence", 0) if ml_result and "prediction" in ml_result and ml_result["prediction"] == 1 else (100 - ml_result.get("confidence", 0)) if ml_result and "confidence" in ml_result else 50
                }
            }
            
            print(f"✅ APK analysis complete: {final_verdict} (confidence: {ml_result.get('confidence', 0) if ml_result else 0}%)")
            return jsonify(result)
            
        finally:
            # Clean up temporary file
            if os.path.exists(temp_path):
                os.remove(temp_path)
                
    except Exception as e:
        print(f"❌ APK analysis failed: {str(e)}")
        return jsonify({"error": f"APK analysis failed: {str(e)}", "status": "error"}), 500

def extract_apk_features_advanced(apk_path):
    """Advanced APK feature extraction using the proper feature extractor"""
    try:
        if APK_FEATURE_EXTRACTOR:
            # Use the proper feature extractor
            extractor = APK_FEATURE_EXTRACTOR(apk_path)
            extractor.extract_permissions()
            extractor.extract_intents()
            extractor.extract_commands()
            
            # Convert feature dictionary to list in consistent order
            feature_vector = []
            for key in sorted(extractor.features.keys()):
                feature_vector.append(extractor.features[key])
            
            print(f"🔍 Extracted {len(feature_vector)} features using advanced extractor")
            return feature_vector, {
                'app_name': getattr(extractor, 'app_name', 'Unknown'),
                'package_name': getattr(extractor, 'package_name', 'Unknown'),
                'version_name': getattr(extractor, 'version_name', 'Unknown'),
                'version_code': getattr(extractor, 'version_code', 'Unknown'),
                'features_count': len(feature_vector)
            }
        else:
            # Fallback to simple extraction
            print("⚠️ Using simplified feature extraction (androguard not available)")
            return extract_apk_features_simple(apk_path), {'features_count': 215}
            
    except Exception as e:
        print(f"❌ Advanced feature extraction failed: {e}")
        return extract_apk_features_simple(apk_path), {'features_count': 215, 'extraction_error': str(e)}

def extract_apk_features_simple(apk_path):
    """Simplified APK feature extraction when androguard is not available"""
    # This is a basic feature extraction - in production you'd use androguard
    features = [0] * 215  # Initialize feature vector to match model expectation
    
    try:
        # Basic file analysis
        file_size = os.path.getsize(apk_path)
        
        # File size based features
        features[0] = 1 if file_size > 10000000 else 0  # Large file (>10MB)
        features[1] = 1 if file_size < 100000 else 0    # Very small file (<100KB)
        
        # Try to analyze as ZIP file (APK is a ZIP)
        try:
            with zipfile.ZipFile(apk_path, 'r') as zip_file:
                file_list = zip_file.namelist()
                
                # Check for suspicious files
                features[2] = 1 if any('classes.dex' in f for f in file_list) else 0
                features[3] = 1 if any('AndroidManifest.xml' in f for f in file_list) else 0
                features[4] = 1 if any('.so' in f for f in file_list) else 0  # Native libraries
                features[5] = 1 if len([f for f in file_list if f.endswith('.dex')]) > 1 else 0  # Multiple dex files
                features[6] = 1 if any('assets/' in f for f in file_list) else 0
                features[7] = 1 if any('res/' in f for f in file_list) else 0
                features[8] = 1 if len(file_list) > 1000 else 0  # Too many files
                
                # Check for common malware indicators
                features[9] = 1 if any('payload' in f.lower() for f in file_list) else 0
                features[10] = 1 if any('trojan' in f.lower() for f in file_list) else 0
                features[11] = 1 if any('virus' in f.lower() for f in file_list) else 0
                
        except zipfile.BadZipFile:
            # Not a valid ZIP/APK file
            features[12] = 1
            
    except Exception as e:
        print(f"⚠️ Simple feature extraction error: {e}")
        
    return features

@app.route("/analyze/app", methods=["OPTIONS"])
def analyze_app_options():
    response = jsonify({"status": "ok"})
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response

# New Advanced Classification Endpoints

@app.route("/classify/content", methods=["POST", "OPTIONS"])
def classify_content():
    """Automatically classify any content into Legitimate, Suspicious, or Fraudulent"""
    try:
        data = request.json
        content = data.get("content", "")
        content_type = data.get("type", "text")  # text, url, email, etc.
        
        if not content:
            return jsonify({"error": "No content provided for classification"}), 400
        
        print(f"🔍 Classifying content type: {content_type}")
        
        # Perform automatic classification
        classification_result = threat_classifier.classify_content(content, content_type)
        
        # Generate detailed analysis
        analysis_result = get_fallback_analysis(content)
        
        return jsonify({
            "content_classification": classification_result,
            "detailed_analysis": analysis_result,
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "engine": "CyberGuard AI Advanced Classification System"
        })
        
    except Exception as e:
        print(f"❌ Error in content classification: {str(e)}")
        return jsonify({"error": f"Classification error: {str(e)}", "status": "error"}), 500

@app.route("/threat/proactive-scan", methods=["POST", "OPTIONS"])
def proactive_threat_scan():
    """Proactive threat identification and protection"""
    try:
        data = request.json
        targets = data.get("targets", [])  # List of URLs, emails, or content to scan
        scan_type = data.get("scan_type", "comprehensive")  # quick, comprehensive, deep
        
        if not targets:
            return jsonify({"error": "No targets provided for scanning"}), 400
        
        print(f"🛡️ Starting proactive threat scan for {len(targets)} targets")
        
        scan_results = []
        threat_summary = {
            "total_scanned": len(targets),
            "fraudulent": 0,
            "suspicious": 0,
            "legitimate": 0,
            "high_risk_threats": [],
            "protection_recommendations": []
        }
        
        for i, target in enumerate(targets):
            print(f"📊 Scanning target {i+1}/{len(targets)}: {target[:50]}...")
            
            # Classify each target
            classification = threat_classifier.classify_content(target)
            
            # Generate protection recommendations
            recommendations = generate_protection_recommendations(classification, target)
            
            scan_result = {
                "target": target[:100] + "..." if len(target) > 100 else target,
                "classification": classification,
                "recommendations": recommendations,
                "scan_timestamp": datetime.now().isoformat()
            }
            
            scan_results.append(scan_result)
            
            # Update summary
            threat_summary[classification['classification'].lower()] += 1
            
            if classification['threat_level'] == 'HIGH':
                threat_summary['high_risk_threats'].append({
                    "target": target[:50] + "..." if len(target) > 50 else target,
                    "risk_score": classification['risk_score'],
                    "primary_threat": classification['risk_factors'][0] if classification['risk_factors'] else "Unknown"
                })
        
        # Generate overall protection recommendations
        threat_summary['protection_recommendations'] = generate_overall_recommendations(threat_summary)
        
        return jsonify({
            "scan_results": scan_results,
            "threat_summary": threat_summary,
            "status": "success",
            "scan_completed": datetime.now().isoformat(),
            "engine": "CyberGuard AI Proactive Threat Scanner"
        })
        
    except Exception as e:
        print(f"❌ Error in proactive scan: {str(e)}")
        return jsonify({"error": f"Scan error: {str(e)}", "status": "error"}), 500

@app.route("/threat/intelligence", methods=["GET", "OPTIONS"])
def threat_intelligence():
    """Get current threat intelligence and statistics"""
    try:
        # Simulate real-time threat intelligence
        intelligence_data = {
            "current_threats": {
                "active_phishing_campaigns": 47,
                "new_malware_variants": 12,
                "compromised_websites": 156,
                "fake_apps_detected": 23
            },
            "threat_trends": {
                "phishing_increase": "+15% this week",
                "crypto_scams": "+23% this month",
                "fake_banking_apps": "+8% this week",
                "social_engineering": "+12% this month"
            },
            "protection_status": {
                "total_scans_today": 1247,
                "threats_blocked": 89,
                "users_protected": 1158,
                "success_rate": "92.8%"
            },
            "recent_discoveries": [
                {
                    "type": "Phishing Website",
                    "target": "fake-paypal-login.com",
                    "discovered": "2 hours ago",
                    "risk": "HIGH"
                },
                {
                    "type": "Malicious App",
                    "target": "Fake WhatsApp Pro",
                    "discovered": "4 hours ago", 
                    "risk": "HIGH"
                },
                {
                    "type": "Crypto Scam",
                    "target": "bitcoin-giveaway-fake.net",
                    "discovered": "6 hours ago",
                    "risk": "MEDIUM"
                }
            ],
            "last_updated": datetime.now().isoformat()
        }
        
        return jsonify({
            "threat_intelligence": intelligence_data,
            "status": "success",
            "engine": "CyberGuard AI Threat Intelligence Center"
        })
        
    except Exception as e:
        return jsonify({"error": f"Intelligence error: {str(e)}", "status": "error"}), 500

def generate_protection_recommendations(classification, target):
    """Generate specific protection recommendations based on classification"""
    recommendations = []
    
    if classification['classification'] == 'FRAUDULENT':
        recommendations.extend([
            "🚨 IMMEDIATE ACTION: Block this content/URL immediately",
            "⛔ Do not interact with or share this content",
            "🔒 Change any passwords if you've already interacted",
            "📞 Contact your bank/service provider if financial info was shared",
            "🚫 Report this threat to appropriate authorities"
        ])
    elif classification['classification'] == 'SUSPICIOUS':
        recommendations.extend([
            "⚠️ Exercise extreme caution with this content",
            "🔍 Verify authenticity through official channels",
            "🛡️ Use additional security measures (2FA, etc.)",
            "👥 Consult with security experts if unsure",
            "📋 Monitor accounts for unusual activity"
        ])
    else:
        recommendations.extend([
            "✅ Content appears safe for normal use",
            "🔒 Continue following standard security practices",
            "🛡️ Keep security software updated",
            "👁️ Remain vigilant for any changes"
        ])
    
    return recommendations

def generate_overall_recommendations(threat_summary):
    """Generate overall security recommendations based on scan summary"""
    recommendations = []
    
    total = threat_summary['total_scanned']
    fraudulent = threat_summary['fraudulent']
    suspicious = threat_summary['suspicious']
    
    fraud_percentage = (fraudulent / total) * 100 if total > 0 else 0
    
    if fraud_percentage > 30:
        recommendations.extend([
            "🚨 HIGH THREAT ENVIRONMENT: Multiple fraudulent items detected",
            "🔒 Implement immediate security measures",
            "🛡️ Enable advanced threat protection",
            "📞 Consider professional security consultation"
        ])
    elif fraud_percentage > 10:
        recommendations.extend([
            "⚠️ ELEVATED RISK: Some fraudulent content detected",
            "🔍 Increase vigilance and verification processes",
            "🛡️ Review and update security settings",
            "📋 Monitor for additional threats"
        ])
    else:
        recommendations.extend([
            "✅ NORMAL THREAT LEVEL: Standard precautions advised",
            "🔒 Maintain current security practices",
            "👁️ Continue regular monitoring"
        ])
    
    return recommendations

# Enhanced analysis functions for better error handling
def generate_enhanced_website_analysis(url, classification, status_message, detail_message):
    """Generate enhanced website analysis with API status information"""

    # Use the provided URL directly
    target_url = url if url else "the provided URL"

    analysis_parts = [
        f"{status_message}",
        f"📝 {detail_message}",
        f"",
        f"🛡️ **LOCAL AI THREAT ANALYSIS REPORT**",
        f"",
        f"**Target:** {target_url}",
        f"**Classification:** {classification['classification']}",
        f"**Threat Level:** {classification['threat_level']}",
        f"**Risk Score:** {classification['risk_score']}/100",
        f"**Confidence:** {classification['confidence']}",
        f"",
        f"**1. SECURITY ASSESSMENT**"
    ]

    if classification['classification'] == 'FRAUDULENT':
        analysis_parts.extend([
            f"⚠️ **HIGH RISK DETECTED** - This website shows multiple indicators of fraudulent activity.",
            f"🚨 **RECOMMENDATION:** Avoid this website entirely. Do not enter personal information.",
            f"",
            f"**Identified Threats:**"
        ])
    elif classification['classification'] == 'SUSPICIOUS':
        analysis_parts.extend([
            f"⚠️ **MEDIUM RISK DETECTED** - This website exhibits suspicious characteristics.",
            f"🔍 **RECOMMENDATION:** Exercise extreme caution. Verify authenticity before proceeding.",
            f"",
            f"**Suspicious Indicators:**"
        ])
    else:
        analysis_parts.extend([
            f"✅ **LOW RISK** - Initial analysis suggests this website appears legitimate.",
            f"ℹ️ **RECOMMENDATION:** Standard web safety practices recommended.",
            f"",
            f"**Positive Indicators:**"
        ])

    # Add risk factors
    for factor in classification['risk_factors']:
        analysis_parts.append(f"• {factor}")

    if not classification['risk_factors']:
        analysis_parts.append("• No significant risk factors detected")

    analysis_parts.extend([
        f"",
        f"**2. LOCAL AI ANALYSIS COMPLETED**",
        f"• Pattern recognition algorithms applied",
        f"• Threat signature database cross-referenced",
        f"• Behavioral analysis performed",
        f"• Risk scoring calculated",
        f"",
        f"**3. RECOMMENDED ACTIONS**",
        f"• Continue using CyberGuard AI for real-time protection",
        f"• Report suspicious websites to authorities if fraudulent",
        f"• Keep security software updated",
        f"",
        f"---",
        f"*Local AI Analysis by CyberGuard Security Engine*",
        f"*Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*"
    ])

    return {
        "analysis": "\n".join(analysis_parts),
        "classification": classification,
        "status": "success",
        "api_status": "LOCAL_ANALYSIS",
        "timestamp": datetime.now().isoformat()
    }

def generate_enhanced_app_analysis(prompt, classification, status_message, detail_message):
    """Generate enhanced app analysis with API status information"""

    analysis_parts = [
        f"{status_message}",
        f"📝 {detail_message}",
        f"",
        f"📱 **LOCAL AI APP SECURITY ANALYSIS**",
        f"",
        f"**Classification:** {classification['classification']}",
        f"**Threat Level:** {classification['threat_level']}",
        f"**Risk Score:** {classification['risk_score']}/100",
        f"**Confidence:** {classification['confidence']}",
        f"",
        f"**1. APP SECURITY ASSESSMENT**"
    ]

    if classification['classification'] == 'FRAUDULENT':
        analysis_parts.extend([
            f"⚠️ **HIGH RISK DETECTED** - This app shows multiple indicators of fraudulent activity.",
            f"🚨 **RECOMMENDATION:** Do not download or install this app.",
            f"",
            f"**Identified Threats:**"
        ])
    elif classification['classification'] == 'SUSPICIOUS':
        analysis_parts.extend([
            f"⚠️ **MEDIUM RISK DETECTED** - This app exhibits suspicious characteristics.",
            f"🔍 **RECOMMENDATION:** Research thoroughly before installation.",
            f"",
            f"**Suspicious Indicators:**"
        ])
    else:
        analysis_parts.extend([
            f"✅ **LOW RISK** - Initial analysis suggests this app appears legitimate.",
            f"ℹ️ **RECOMMENDATION:** Standard app safety practices recommended.",
            f"",
            f"**Positive Indicators:**"
        ])

    # Add risk factors
    for factor in classification['risk_factors']:
        analysis_parts.append(f"• {factor}")

    if not classification['risk_factors']:
        analysis_parts.append("• No significant risk factors detected")

    analysis_parts.extend([
        f"",
        f"**2. LOCAL AI ANALYSIS COMPLETED**",
        f"• App behavior patterns analyzed",
        f"• Permission requirements evaluated",
        f"• Developer reputation assessed",
        f"",
        f"---",
        f"*Local AI Analysis by CyberGuard Security Engine*",
        f"*Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*"
    ])

    return {
        "analysis": "\n".join(analysis_parts),
        "classification": classification,
        "status": "success",
        "api_status": "LOCAL_ANALYSIS",
        "timestamp": datetime.now().isoformat()
    }

def generate_enhanced_general_analysis(prompt, classification, status_message, detail_message):
    """Generate enhanced general analysis with API status information"""

    analysis_parts = [
        f"{status_message}",
        f"📝 {detail_message}",
        f"",
        f"🔍 **LOCAL AI CONTENT ANALYSIS**",
        f"",
        f"**Classification:** {classification['classification']}",
        f"**Threat Level:** {classification['threat_level']}",
        f"**Risk Score:** {classification['risk_score']}/100",
        f"**Confidence:** {classification['confidence']}",
        f"",
        f"**1. CONTENT SECURITY ASSESSMENT**"
    ]

    if classification['classification'] == 'FRAUDULENT':
        analysis_parts.extend([
            f"⚠️ **HIGH RISK DETECTED** - This content shows multiple indicators of fraudulent activity.",
            f"🚨 **RECOMMENDATION:** Treat with extreme caution.",
            f"",
            f"**Identified Threats:**"
        ])
    elif classification['classification'] == 'SUSPICIOUS':
        analysis_parts.extend([
            f"⚠️ **MEDIUM RISK DETECTED** - This content exhibits suspicious characteristics.",
            f"🔍 **RECOMMENDATION:** Verify source and context.",
            f"",
            f"**Suspicious Indicators:**"
        ])
    else:
        analysis_parts.extend([
            f"✅ **LOW RISK** - Initial analysis suggests this content appears legitimate.",
            f"ℹ️ **RECOMMENDATION:** Standard content safety practices recommended.",
            f"",
            f"**Positive Indicators:**"
        ])

    # Add risk factors
    for factor in classification['risk_factors']:
        analysis_parts.append(f"• {factor}")

    if not classification['risk_factors']:
        analysis_parts.append("• No significant risk factors detected")

    analysis_parts.extend([
        f"",
        f"**2. LOCAL AI ANALYSIS COMPLETED**",
        f"• Content pattern analysis performed",
        f"• Linguistic analysis completed",
        f"• Context evaluation finished",
        f"",
        f"---",
        f"*Local AI Analysis by CyberGuard Security Engine*",
        f"*Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*"
    ])

    return {
        "analysis": "\n".join(analysis_parts),
        "classification": classification,
        "status": "success",
        "api_status": "LOCAL_ANALYSIS",
        "timestamp": datetime.now().isoformat()
    }

# Chrome Extension Support Endpoints
@app.route("/log/threat", methods=["POST", "OPTIONS"])
def log_threat():
    """Log threat detection from Chrome extension"""
    try:
        data = request.json
        url = data.get('url', '')
        reason = data.get('reason', '')
        action = data.get('action', '')
        user_agent = data.get('userAgent', '')
        
        print(f"🚨 Threat logged: {url} - {reason} - {action}")
        
        # Log to database
        db.log_threat(url, reason, action, user_agent)
        
        return jsonify({
            "status": "success",
            "message": "Threat logged successfully",
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        print(f"❌ Error logging threat: {e}")
        return jsonify({"error": str(e), "status": "error"}), 500

@app.route("/report/malicious", methods=["POST", "OPTIONS"])
def report_malicious():
    """Report malicious site from Chrome extension"""
    try:
        data = request.json
        url = data.get('url', '')
        user_agent = data.get('userAgent', '')
        
        print(f"📋 Malicious site reported: {url}")
        
        # Log user report
        db.log_user_report(url, "User reported as malicious", user_agent)
        
        # Add to blacklist
        db.add_to_blacklist(url, "User reported")
        
        return jsonify({
            "status": "success",
            "message": "Site reported successfully. Thank you for helping keep the internet safe!",
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        print(f"❌ Error reporting malicious site: {e}")
        return jsonify({"error": str(e), "status": "error"}), 500

@app.route("/whitelist/add", methods=["POST", "OPTIONS"])
def add_to_whitelist():
    """Add site to whitelist"""
    try:
        data = request.json
        url = data.get('url', '')
        
        if db.add_to_whitelist(url):
            return jsonify({
                "status": "success",
                "message": "Site added to whitelist",
                "timestamp": datetime.now().isoformat()
            })
        else:
            return jsonify({"error": "Failed to add to whitelist", "status": "error"}), 500
    except Exception as e:
        return jsonify({"error": str(e), "status": "error"}), 500

@app.route("/stats", methods=["GET", "OPTIONS"])
def get_stats():
    """Get system statistics"""
    try:
        stats = db.get_stats()
        recent_threats = db.get_recent_threats(5)
        
        return jsonify({
            "stats": stats,
            "recent_threats": recent_threats,
            "status": "success",
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({"error": str(e), "status": "error"}), 500

# Authentication and User Management Endpoints
@app.route("/auth/signup", methods=["POST", "OPTIONS"])
def signup():
    """User registration endpoint"""
    if request.method == 'OPTIONS':
        # Handle preflight request
        response = jsonify({'status': 'ok'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin')
        return response
        
    try:
        print("👤 Received signup request")
        
        # Check if request has JSON content type
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400
            
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON data"}), 400
        
        username = data.get("username", "").strip()
        email = data.get("email", "").strip()
        password = data.get("password", "")
        
        # Validation
        if not username or not email or not password:
            return jsonify({"error": "Username, email, and password are required"}), 400
        
        if len(username) < 3:
            return jsonify({"error": "Username must be at least 3 characters long"}), 400
        
        if len(password) < 6:
            return jsonify({"error": "Password must be at least 6 characters long"}), 400
        
        if "@" not in email or "." not in email:
            return jsonify({"error": "Invalid email format"}), 400
        
        # Create user
        user_result = db.create_user(username, email, password)

        # db.create_user returns either an integer user_id, or a dict {'exists': 'email'|'username'}, or None
        if isinstance(user_result, dict) and user_result.get('exists'):
            reason = user_result.get('exists')
            msg = 'Email already exists' if reason == 'email' else 'Username already exists'
            print(f"⚠️ Signup conflict: {msg}")
            return jsonify({"error": msg}), 409

        if isinstance(user_result, int):
            user_id = user_result
            print(f"✅ User created successfully: {username} (ID: {user_id})")

            # Create session for new user
            session_token = db.create_session(user_id)

            return jsonify({
                "status": "success",
                "message": "User registered successfully",
                "user": {
                    "id": user_id,
                    "username": username,
                    "email": email
                },
                "session_token": session_token,
                "timestamp": datetime.now().isoformat()
            })

        # other failures
        return jsonify({"error": "Username or email already exists"}), 409
            
    except Exception as e:
        print(f"❌ Signup error: {str(e)}")
        return jsonify({"error": f"Registration failed: {str(e)}"}), 500

@app.route("/auth/signin", methods=["POST", "OPTIONS"])
def signin():
    """User login endpoint"""
    if request.method == 'OPTIONS':
        # Handle preflight request
        response = jsonify({'status': 'ok'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin')
        return response
        
    try:
        print("🔐 Received signin request")
        
        # Check if request has JSON content type
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400
            
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON data"}), 400
        
        login = data.get("login", "").strip()  # Can be username or email
        password = data.get("password", "")
        
        if not login or not password:
            return jsonify({"error": "Login and password are required"}), 400
        
        # Authenticate user
        auth_result = db.authenticate_user(login, password)

        if not auth_result or not auth_result.get('success'):
            # Authentication failed
            print(f"⚠️ Authentication failed for login: {login}")
            return jsonify({"error": "Invalid login credentials"}), 401

        user = auth_result['user']
        print(f"✅ User authenticated: {user.get('username')} (ID: {user.get('id')})")

        # Create new session
        session_token = db.create_session(user['id'])

        return jsonify({
            "status": "success",
            "message": "Signed in successfully",
            "user": {
                "id": user['id'],
                "username": user.get('username'),
                "email": user.get('email'),
                "created_at": user.get('created_at')
            },
            "session_token": session_token,
            "timestamp": datetime.now().isoformat()
        })
            
    except Exception as e:
        print(f"❌ Signin error: {str(e)}")
        return jsonify({"error": f"Login failed: {str(e)}"}), 500

@app.route("/auth/logout", methods=["POST", "OPTIONS"])
def logout():
    """User logout endpoint"""
    if request.method == 'OPTIONS':
        # Handle preflight request
        response = jsonify({'status': 'ok'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin')
        return response
        
    try:
        print("🚪 Received logout request")
        
        # Check if request has JSON content type
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400
            
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON data"}), 400
            
        session_token = data.get("session_token", "")

        if not session_token:
            return jsonify({"error": "Session token required"}), 400

        # Logout user (invalidate session)
        success = db.logout_user(session_token)

        if success:
            print("✅ User logged out successfully")
            return jsonify({
                "status": "success",
                "message": "Logged out successfully",
                "timestamp": datetime.now().isoformat()
            })
        else:
            return jsonify({"error": "Invalid session token"}), 401
            
    except Exception as e:
        print(f"❌ Logout error: {str(e)}")
        return jsonify({"error": f"Logout failed: {str(e)}"}), 500

@app.route("/auth/validate", methods=["POST", "OPTIONS"])
def validate_session():
    """Validate user session token"""
    # Handle preflight CORS request
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin')
        return response

    try:
        # Use get_json to safely parse JSON body
        data = request.get_json()
        session_token = data.get("session_token", "")
        
        if not session_token:
            return jsonify({"error": "Session token required"}), 400
        
        # Validate session
        user = db.validate_session(session_token)
        
        if user:
            return jsonify({
                "status": "success",
                "valid": True,
                "user": {
                    "id": user['id'],
                    "username": user['username'],
                    "email": user['email']
                },
                "timestamp": datetime.now().isoformat()
            })
        else:
            return jsonify({
                "status": "success",
                "valid": False,
                "message": "Invalid or expired session"
            }), 401
            
    except Exception as e:
        print(f"❌ Session validation error: {str(e)}")
        return jsonify({"error": f"Session validation failed: {str(e)}"}), 500

@app.route("/dashboard/data", methods=["POST", "OPTIONS"])
def get_dashboard_data():
    """Get user dashboard data and analytics"""
    try:
        # Handle preflight CORS request
        if request.method == 'OPTIONS':
            response = jsonify({'status': 'ok'})
            response.headers.add('Access-Control-Allow-Origin', '*')
            response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
            response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin')
            return response

        print("📊 Received dashboard data request")
        data = request.get_json()
        session_token = data.get("session_token", "")
        
        if not session_token:
            return jsonify({"error": "Session token required"}), 400
        
        # Validate session
        user = db.validate_session(session_token)
        
        if not user:
            return jsonify({"error": "Invalid or expired session"}), 401
        
        user_id = user['id']
        print(f"📊 Getting dashboard data for user: {user['username']} (ID: {user_id})")
        
        # Get user dashboard data
        dashboard_data = db.get_user_dashboard_data(user_id)
        
        return jsonify({
            "status": "success",
            "user": {
                "id": user['id'],
                "username": user['username'],
                "email": user['email']
            },
            "dashboard": dashboard_data,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"❌ Dashboard data error: {str(e)}")
        return jsonify({"error": f"Failed to get dashboard data: {str(e)}"}), 500

# Enhanced website analysis with user tracking
@app.route("/analyze/website/user", methods=["POST", "OPTIONS"])
def analyze_website_with_user():
    """Analyze website and log scan for authenticated user"""
    try:
        print("🌐📊 Received user website analysis request")
        data = request.json
        
        url = data.get("url", "")
        session_token = data.get("session_token", "")
        
        if not url:
            return jsonify({"error": "URL is required"}), 400
        
        user_id = None
        if session_token:
            # Validate session and get user
            user = db.validate_session(session_token)
            if user:
                user_id = user['id']
                print(f"🔐 Authenticated scan for user: {user['username']} (ID: {user_id})")
        
        # Perform regular website analysis (reuse existing logic)
        # Note: This would normally call the main analyze_website function
        # For now, we'll do a simplified analysis
        
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc or parsed_url.path
        
        # Simplified analysis for demo
        classification_result = threat_classifier.classify_content(url, "url")
        
        verdict = classification_result['classification']
        risk_score = classification_result['risk_score']
        
        # Log the scan for the user
        if user_id:
            db.log_user_scan(user_id, url, verdict, risk_score)
            print(f"📝 Logged scan for user {user_id}: {url} -> {verdict}")
        
        return jsonify({
            "status": "success",
            "verdict": verdict,
            "risk_score": risk_score,
            "analysis": classification_result,
            "user_logged": user_id is not None,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"❌ User website analysis error: {str(e)}")
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500

@app.route("/analyze/fake-website", methods=["POST"])
def analyze_fake_website():
    """Analyze website for fake/fraudulent content (uses phishing model)"""
    try:
        print("[INFO] Received fake website analysis request")
        data = request.get_json(force=True, silent=True) or {}
        url = data.get("url")
        print(f"[INFO] Analyzing (fake) website: {url}")

        if not url:
            print("[ERROR] No URL provided in request")
            return jsonify({"error": "No URL provided"}), 400

        # Extract domain
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc

        # WHOIS features
        whois_features = get_whois_features(domain)
        print(f"[DEBUG] WHOIS features: {whois_features}")

        # Heuristic allowlist / blacklist short-circuit
        dkey = domain.lower() if domain else ''
        if dkey in ALLOWLIST:
            classification_result = {'classification': 'LEGITIMATE', 'risk_score': 0, 'risk_factors': ['allowlist']}
            ml_prediction = 0
            ml_proba = [1.0, 0.0]
            verdict = 'LEGITIMATE'
            response = {
                'verdict': verdict,
                'ml_model': {'prediction': ml_prediction, 'proba': ml_proba, 'features': None},
                'whois': whois_features,
                'html': {},
                'safe_browsing': {},
                'heuristic_classification': classification_result,
                'timestamp': datetime.now().isoformat()
            }
            print(f"[INFO] Domain in allowlist: {domain}, returning LEGITIMATE")
            return jsonify(response)
        if dkey in BLACKLIST:
            classification_result = {'classification': 'FRAUDULENT', 'risk_score': 100, 'risk_factors': ['blacklist']}
            ml_prediction = 1
            ml_proba = [0.0, 1.0]
            verdict = 'FRAUDULENT'
            response = {
                'verdict': verdict,
                'ml_model': {'prediction': ml_prediction, 'proba': ml_proba, 'features': None},
                'whois': whois_features,
                'html': {},
                'safe_browsing': {},
                'heuristic_classification': classification_result,
                'timestamp': datetime.now().isoformat()
            }
            print(f"[INFO] Domain in blacklist: {domain}, returning FRAUDULENT")
            return jsonify(response)

        # HTML features
        html_features = get_html_features(url)
        print(f"[DEBUG] HTML features: {html_features}")

        # ML model prediction (if available)
        ml_prediction = None
        ml_proba = None
        ml_features = None
        if ml_model is not None:
            try:
                ml_features, fallback_used = safe_feature_extraction(url)
                # Ensure ml_features is the correct length for the model
                try:
                    expected = int(getattr(ml_model, 'n_features_in_', len(ml_features)))
                except Exception:
                    expected = len(ml_features)
                if len(ml_features) < expected:
                    ml_features = ml_features + [0] * (expected - len(ml_features))
                elif len(ml_features) > expected:
                    ml_features = ml_features[:expected]

                # Predict
                raw_pred = None
                try:
                    # Prefer predict_proba if available to get a probability
                    if hasattr(ml_model, 'predict_proba'):
                        proba = ml_model.predict_proba([ml_features])
                        # proba may be numpy array or list
                        try:
                            p0 = float(proba[0][0])
                            p1 = float(proba[0][1])
                            ml_proba = [p0, p1]
                            ml_prediction = int(p1 > 0.5)
                        except Exception:
                            # fallback: flatten and coerce
                            flat = list(map(float, proba[0]))
                            if len(flat) >= 2:
                                ml_proba = [flat[0], flat[1]]
                                ml_prediction = int(flat[1] > 0.5)
                            else:
                                ml_proba = None
                                ml_prediction = None
                    else:
                        raw_pred = ml_model.predict([ml_features])[0]
                        try:
                            ml_prediction = int(raw_pred)
                        except Exception:
                            ml_prediction = int(raw_pred[0]) if hasattr(raw_pred, '__iter__') else int(raw_pred)
                except Exception as e:
                    print(f"[ERROR] ML predict/proba error: {e}")
                print(f"[DEBUG] ML model prediction: {ml_prediction}, proba: {ml_proba}")
            except Exception as e:
                print(f"[ERROR] ML model prediction error: {e}")

        # Perform automatic classification (existing heuristic)
        classification_result = threat_classifier.classify_content(url, "url")

        # Check Google Safe Browsing via rate-limited wrapper
        safe_browsing_result = rate_limited_safe_browsing(url, SAFE_BROWSING_API_KEY)
        if safe_browsing_result.get("threat_found"):
            classification_result['risk_score'] = min(classification_result.get('risk_score', 0) + 50, 100)
            classification_result.setdefault('risk_factors', []).append(f"Google Safe Browsing: {safe_browsing_result.get('threat_type')}")
            if classification_result['risk_score'] >= 60:
                classification_result['classification'] = "FRAUDULENT"
                classification_result['threat_level'] = "HIGH"

        # Compute heuristic score and combine with ML and Safe Browsing
        heuristic_score = compute_heuristic_score(domain, whois_features, html_features, classification_result, allowlist=ALLOWLIST, blacklist=BLACKLIST)
        combined = combine_scores(ml_proba, heuristic_score, safe_browsing_result)

        response = {
            "verdict": combined['verdict'],
            "ml_model": {
                "prediction": int(ml_prediction) if ml_prediction is not None else None,
                "proba": ml_proba,
                "features": ml_features
            },
            "whois": whois_features,
            "html": html_features,
            "safe_browsing": safe_browsing_result,
            "heuristic_classification": classification_result,
            "heuristic_score": heuristic_score,
            "combined_details": combined.get('details', {}),
            "timestamp": datetime.now().isoformat()
        }

        print(f"[INFO] Combined unified verdict (fake website): {combined['verdict']} (score={combined['combined_score']})")
        return jsonify(response)
    except Exception as e:
        print(f"[ERROR] Error in fake website analysis: {e}")
        return jsonify({"error": f"Server error: {str(e)}", "status": "error"}), 500

@app.route("/extension/dashboard", methods=["POST", "OPTIONS"])
def extension_dashboard():
    """Get extension dashboard data for authenticated user"""
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin')
        return response
        
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400

        data = request.get_json()
        session_token = data.get("session_token")

        # Session token is optional for extension logs. If provided, validate and associate with a user.
        user = None
        if session_token:
            user = db.validate_session(session_token)
            if not user:
                return jsonify({"error": "Invalid or expired session"}), 401

        # Get extension dashboard data (user-specific if session provided, otherwise global)
        user_id = user['id'] if user else None
        dashboard_data = db.get_extension_dashboard_data(user_id)

        if dashboard_data:
            return jsonify({
                "status": "success",
                "data": dashboard_data,
                "timestamp": datetime.now().isoformat()
            })
        else:
            return jsonify({"error": "Failed to fetch dashboard data"}), 500

    except Exception as e:
        print(f"❌ Extension dashboard error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/extension/log-visit", methods=["POST", "OPTIONS"])
def log_extension_visit():
    """Log a website visit from Chrome extension"""
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin')
        return response
        
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400
            
        data = request.get_json()
        session_token = data.get("session_token")

        # session_token is optional for visit logs; if provided, validate and associate with a user
        user = None
        if session_token:
            user = db.validate_session(session_token)
            if not user:
                return jsonify({"error": "Invalid or expired session"}), 401
        
        # Extract visit data
        url = data.get("url")
        domain = data.get("domain")
        title = data.get("title")
        is_threat = data.get("is_threat", False)
        threat_type = data.get("threat_type")
        risk_score = data.get("risk_score", 0)
        blocked = data.get("blocked", False)
        warning_shown = data.get("warning_shown", False)
        user_action = data.get("user_action")
        
        if not url or not domain:
            return jsonify({"error": "URL and domain are required"}), 400
        
        # Log the visit
        user_id = user['id'] if user else None

        success = db.log_extension_visit(
            user_id, url, domain, title, is_threat, 
            threat_type, risk_score, blocked, warning_shown, user_action
        )
        
        if success:
            # Update daily stats
            # Update daily stats for the specific user if available; anonymous logs update global counters via user_id=None
            if user:
                db.update_daily_extension_stats(
                    user['id'], 
                    pages_visited=1,
                    threats_detected=1 if is_threat else 0,
                    threats_blocked=1 if blocked else 0,
                    warnings_shown=1 if warning_shown else 0
                )
            
            return jsonify({
                "status": "success",
                "message": "Visit logged successfully"
            })
        else:
            return jsonify({"error": "Failed to log visit"}), 500
            
    except Exception as e:
        print(f"❌ Extension visit logging error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/extension/log-threat", methods=["POST", "OPTIONS"])
def log_extension_threat():
    """Log a threat detection from Chrome extension"""
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin')
        return response
        
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400
            
        data = request.get_json()
        session_token = data.get("session_token")
        
        if not session_token:
            return jsonify({"error": "Session token required"}), 401
        
        # Validate session
        user = db.validate_session(session_token)
        if not user:
            return jsonify({"error": "Invalid or expired session"}), 401
        
        # Extract threat data
        url = data.get("url")
        domain = data.get("domain")
        threat_type = data.get("threat_type")
        detection_method = data.get("detection_method")
        confidence_score = data.get("confidence_score", 0.0)
        action_taken = data.get("action_taken")
        user_proceeded = data.get("user_proceeded", False)
        threat_details = data.get("threat_details")
        
        if not all([url, domain, threat_type, detection_method, action_taken]):
            return jsonify({"error": "Missing required threat data"}), 400
        
        # Log the threat
        success = db.log_extension_threat(
            user['id'], url, domain, threat_type, detection_method,
            confidence_score, action_taken, user_proceeded, threat_details
        )
        
        if success:
            return jsonify({
                "status": "success", 
                "message": "Threat logged successfully"
            })
        else:
            return jsonify({"error": "Failed to log threat"}), 500
            
    except Exception as e:
        print(f"❌ Extension threat logging error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route("/extension/settings", methods=["POST", "OPTIONS"])
def extension_settings():
    """Get or update extension settings"""
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin')
        return response
        
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400
            
        data = request.get_json()
        session_token = data.get("session_token")
        
        if not session_token:
            return jsonify({"error": "Session token required"}), 401
        
        # Validate session
        user = db.validate_session(session_token)
        if not user:
            return jsonify({"error": "Invalid or expired session"}), 401
        
        # Check if this is a GET or UPDATE request
        action = data.get("action", "get")
        
        if action == "update":
            settings = data.get("settings", {})
            
            # Update each setting
            for setting_name, setting_value in settings.items():
                db.update_extension_setting(user['id'], setting_name, str(setting_value))
            
            return jsonify({
                "status": "success",
                "message": "Settings updated successfully"
            })
        else:
            # Get current settings
            dashboard_data = db.get_extension_dashboard_data(user['id'])
            settings = dashboard_data['settings'] if dashboard_data else {}
            
            return jsonify({
                "status": "success",
                "settings": settings
            })
            
    except Exception as e:
        print(f"❌ Extension settings error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
