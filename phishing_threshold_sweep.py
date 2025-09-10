import os
import sys
import pandas as pd
import joblib
import statistics

ROOT = os.path.join(os.path.dirname(__file__), 'Phishing_ML', 'Phishing-Website-Detection-by-Machine-Learning-Techniques')
PHISHING_CSV = os.path.join(ROOT, 'DataFiles', '4.phishing.csv')
LEGIT_CSV = os.path.join(ROOT, 'DataFiles', '3.legitimate.csv')
XGB_JSON = os.path.join(ROOT, 'XGBoostClassifier.json')
JOBLIB_XGB = os.path.join(ROOT, 'Phishing_XGB_Model.joblib')

sys.path.append(os.path.abspath(ROOT))
from URLFeatureExtraction import featureExtraction as project_feature_extraction


def load_rows(csv_path, label):
    df = pd.read_csv(csv_path, header=None)
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
            f = None
        feats.append(f)
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
    if os.path.exists(JOBLIB_XGB):
        mdl = joblib.load(JOBLIB_XGB)
        def predict_proba(X):
            return mdl.predict_proba(X)
        return predict_proba, 'joblib_xgb'
    raise RuntimeError('No model found')


def main():
    pos = load_rows(PHISHING_CSV, 1)
    neg = load_rows(LEGIT_CSV, 0)
    data = pos + neg
    urls, labels = zip(*data)
    print('Extracting features for', len(urls), 'rows...')
    feats = extract_features(urls)
    predict_proba, src = load_model_predict_proba()
    print('Loaded model:', src)
    probs = predict_proba(feats)
    probs = [float(p[1]) for p in probs]

    # overall stats
    print('\nProbability stats: min', min(probs), 'max', max(probs), 'mean', statistics.mean(probs))

    thresholds = [0.5, 0.3, 0.1, 0.05, 0.01, 0.001]
    print('\nThreshold sweep:')
    for t in thresholds:
        preds = [1 if p > t else 0 for p in probs]
        tp = sum(1 for y,pred in zip(labels,preds) if y==1 and pred==1)
        tn = sum(1 for y,pred in zip(labels,preds) if y==0 and pred==0)
        fp = sum(1 for y,pred in zip(labels,preds) if y==0 and pred==1)
        fn = sum(1 for y,pred in zip(labels,preds) if y==1 and pred==0)
        total = len(labels)
        acc = (tp+tn)/total
        prec = tp/(tp+fp) if (tp+fp)>0 else 0.0
        rec = tp/(tp+fn) if (tp+fn)>0 else 0.0
        print(f'  > {t:.4f}: positives={sum(preds)}, TP={tp}, FP={fp}, TN={tn}, FN={fn}, acc={acc:.4f}, prec={prec:.4f}, rec={rec:.4f}')

    # top/bottom examples
    paired = list(zip(urls, labels, probs))
    top = sorted(paired, key=lambda x: x[2], reverse=True)[:20]
    bot = sorted(paired, key=lambda x: x[2])[:20]

    print('\nTop 20 by predicted probability:')
    for u,y,p in top:
        print(f"{p:.8f}\t{y}\t{u[:200]}")

    print('\nBottom 20 by predicted probability:')
    for u,y,p in bot:
        print(f"{p:.8f}\t{y}\t{u[:200]}")

if __name__ == '__main__':
    main()
