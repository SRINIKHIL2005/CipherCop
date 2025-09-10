import os
import sys
import pandas as pd
import json
import joblib

ROOT = os.path.join(os.path.dirname(__file__), 'Phishing_ML', 'Phishing-Website-Detection-by-Machine-Learning-Techniques')
PHISHING_CSV = os.path.join(ROOT, 'DataFiles', '4.phishing.csv')
XGB_JSON = os.path.join(ROOT, 'XGBoostClassifier.json')
JOBLIB_XGB = os.path.join(ROOT, 'Phishing_XGB_Model.joblib')

sys.path.append(os.path.abspath(ROOT))
from URLFeatureExtraction import featureExtraction as project_feature_extraction


def load_first_n_phishing(n=20):
    df = pd.read_csv(PHISHING_CSV, header=None)
    urls = df.iloc[:,0].astype(str).tolist()
    return urls[:n]


def extract_features(urls):
    feats = []
    for u in urls:
        try:
            f = project_feature_extraction(u)
            if hasattr(f, 'tolist'):
                f = list(f.tolist())
            elif isinstance(f, dict):
                f = [f[k] for k in sorted(f.keys())]
            elif isinstance(f, (list, tuple)):
                f = list(f)
        except Exception as e:
            # fallback: will try to infer length from previous or use 0s
            print(f"[WARN] feature extraction failed for {u}: {e}")
            f = None
        feats.append(f)
    # replace None with zero vectors of inferred length
    inferred_len = None
    for f in feats:
        if f is not None:
            inferred_len = len(f)
            break
    if inferred_len is None:
        inferred_len = 30
    feats = [f if f is not None else [0]*inferred_len for f in feats]
    return feats


def load_model_predict_proba():
    if os.path.exists(XGB_JSON):
        try:
            import xgboost as xgb
            b = xgb.Booster()
            b.load_model(XGB_JSON)
            def predict_proba(X):
                import pandas as _pd
                df = _pd.DataFrame(X)
                dm = xgb.DMatrix(df)
                p = b.predict(dm)
                return [[1-pi, pi] for pi in p]
            return predict_proba, 'xgb_json'
        except Exception as e:
            print('[WARN] failed to load XGBoost JSON:', e)
    if os.path.exists(JOBLIB_XGB):
        try:
            mdl = joblib.load(JOBLIB_XGB)
            def predict_proba(X):
                return mdl.predict_proba(X)
            return predict_proba, 'joblib_xgb'
        except Exception as e:
            print('[WARN] failed to load joblib xgb:', e)
    raise RuntimeError('No model found')


def main():
    urls = load_first_n_phishing(20)
    feats = extract_features(urls)
    predict_proba, src = load_model_predict_proba()
    print(f"Loaded model source: {src}")

    probs = predict_proba(feats)
    # normalize shape
    probs = [[float(p[0]), float(p[1])] for p in probs]

    print('\nFirst 20 phishing URL probabilities (index,prob_pos,url sample):')
    for i, (u, p) in enumerate(zip(urls, probs)):
        print(f"{i+1:02d}. {p[1]:.6f}  {u[:120]}")

    import statistics
    pos_vals = [p[1] for p in probs]
    print('\nProbability stats for these 20 rows:')
    print('min:', min(pos_vals))
    print('max:', max(pos_vals))
    print('mean:', statistics.mean(pos_vals))

    thresholds = [0.5, 0.3, 0.1, 0.05]
    print('\nThreshold sweep counts:')
    for t in thresholds:
        cnt = sum(1 for p in probs if p[1] > t)
        print(f'  > {t:.2f}: {cnt}/{len(probs)}')

if __name__ == '__main__':
    main()
