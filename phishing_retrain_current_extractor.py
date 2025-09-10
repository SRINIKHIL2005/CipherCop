import os
import sys
import pandas as pd
import joblib
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, confusion_matrix

ROOT = os.path.join(os.path.dirname(__file__), 'Phishing_ML', 'Phishing-Website-Detection-by-Machine-Learning-Techniques')
PHISHING_CSV = os.path.join(ROOT, 'DataFiles', '4.phishing.csv')
LEGIT_CSV = os.path.join(ROOT, 'DataFiles', '3.legitimate.csv')
XGB_JSON_OUT = os.path.join(ROOT, 'XGBoostClassifier_retrained.json')
JOBLIB_OUT = os.path.join(ROOT, 'Phishing_XGB_Model_retrained.joblib')

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
        inferred_len = 16
    feats = [f if f is not None else [0]*inferred_len for f in feats]
    return feats


def main():
    pos = load_rows(PHISHING_CSV, 1)
    neg = load_rows(LEGIT_CSV, 0)
    data = pos + neg
    urls, labels = zip(*data)
    print('Extracting features for', len(urls), 'rows...')
    X = extract_features(urls)
    X = pd.DataFrame(X)
    y = np.array(labels)

    # train/test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
    print('Train shape:', X_train.shape, 'Test shape:', X_test.shape)

    try:
        from xgboost import XGBClassifier
    except Exception as e:
        print('XGBoost not installed or import failed:', e)
        raise

    clf = XGBClassifier(use_label_encoder=False, eval_metric='logloss', n_estimators=200, max_depth=4, random_state=42)
    print('Training XGBoost...')
    clf.fit(X_train, y_train)

    # evaluate
    probs = clf.predict_proba(X_test)[:,1]
    preds = (probs > 0.5).astype(int)
    acc = accuracy_score(y_test, preds)
    prec = precision_score(y_test, preds, zero_division=0)
    rec = recall_score(y_test, preds, zero_division=0)
    cm = confusion_matrix(y_test, preds)
    print('Evaluation on holdout:')
    print(' Accuracy:', acc)
    print(' Precision:', prec)
    print(' Recall:', rec)
    print(' Confusion matrix:\n', cm)

    # save artifacts
    print('Saving artifacts:')
    try:
        booster = clf.get_booster()
        booster.save_model(XGB_JSON_OUT)
        print(' Wrote', XGB_JSON_OUT)
    except Exception as e:
        print(' Failed to save booster JSON:', e)
    try:
        joblib.dump(clf, JOBLIB_OUT)
        print(' Wrote', JOBLIB_OUT)
    except Exception as e:
        print(' Failed to save joblib:', e)

    print('Done')

if __name__ == '__main__':
    main()
