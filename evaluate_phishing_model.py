import os
import pandas as pd
import json
import joblib
from sklearn.metrics import accuracy_score, precision_score, recall_score, confusion_matrix

# Adjust these paths if your workspace differs
ROOT = os.path.join(os.path.dirname(__file__), 'Phishing_ML', 'Phishing-Website-Detection-by-Machine-Learning-Techniques')
PHISHING_CSV = os.path.join(ROOT, 'DataFiles', '4.phishing.csv')
LEGIT_CSV = os.path.join(ROOT, 'DataFiles', '3.legitimate.csv')
FEATURE_EXTRACTOR = os.path.join(ROOT, 'URLFeatureExtraction.py')
XGB_JSON = os.path.join(ROOT, 'XGBoostClassifier.json')
JOBLIB_XGB = os.path.join(ROOT, 'Phishing_XGB_Model.joblib')

import sys
sys.path.append(os.path.abspath(ROOT))
from URLFeatureExtraction import featureExtraction as project_feature_extraction

def load_rows(csv_path, label):
    df = pd.read_csv(csv_path, header=None)
    # many datasets put the URL in first column; adapt if different
    urls = df.iloc[:,0].astype(str).tolist()
    return [(u, label) for u in urls]

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
        except Exception:
            f = [0]*30
        feats.append(f)
    return feats

def load_model():
    if os.path.exists(XGB_JSON):
        import xgboost as xgb
        b = xgb.Booster()
        b.load_model(XGB_JSON)
        def predict_proba(X):
            import pandas as _pd
            df = _pd.DataFrame(X)
            dm = xgb.DMatrix(df)
            p = b.predict(dm)
            return [[1-pi, pi] for pi in p]
        return predict_proba
    if os.path.exists(JOBLIB_XGB):
        mdl = joblib.load(JOBLIB_XGB)
        def predict_proba(X):
            return mdl.predict_proba(X)
        return predict_proba
    raise RuntimeError('No model found')

def main():
    pos = load_rows(PHISHING_CSV, 1)
    neg = load_rows(LEGIT_CSV, 0)
    data = pos + neg
    urls, labels = zip(*data)
    feats = extract_features(urls)

    predict_proba = load_model()
    probs = predict_proba(feats)
    preds = [int(p[1] > 0.5) for p in probs]

    print('Accuracy:', accuracy_score(labels, preds))
    print('Precision:', precision_score(labels, preds, zero_division=0))
    print('Recall:', recall_score(labels, preds, zero_division=0))
    print('Confusion matrix:\n', confusion_matrix(labels, preds))

if __name__ == '__main__':
    main()
