import os
import sys
import random
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, confusion_matrix

ROOT = os.path.join(os.path.dirname(__file__), 'Phishing_ML', 'Phishing-Website-Detection-by-Machine-Learning-Techniques')
PHISHING_CSV = os.path.join(ROOT, 'DataFiles', '4.phishing.csv')
LEGIT_CSV = os.path.join(ROOT, 'DataFiles', '3.legitimate.csv')
OUT_JSON = os.path.join(ROOT, 'XGBoostClassifier_original_features.json')
OUT_JOBLIB = os.path.join(ROOT, 'Phishing_XGB_Model_original_features.joblib')

sys.path.append(os.path.abspath(ROOT))
from URLFeatureExtraction import featureExtraction as original_feature_extraction


def load_sample(n_per_class=1000):
    pos_df = pd.read_csv(PHISHING_CSV, header=None).iloc[:,0].astype(str)
    neg_df = pd.read_csv(LEGIT_CSV, header=None).iloc[:,0].astype(str)
    pos_sample = pos_df.sample(n=min(len(pos_df), n_per_class), random_state=42).tolist()
    neg_sample = neg_df.sample(n=min(len(neg_df), n_per_class), random_state=42).tolist()
    urls = pos_sample + neg_sample
    labels = [1]*len(pos_sample) + [0]*len(neg_sample)
    return urls, labels


def extract_features(urls):
    feats = []
    for i,u in enumerate(urls):
        try:
            f = original_feature_extraction(u, offline=False)
            if hasattr(f, 'tolist'):
                f = list(f.tolist())
            elif isinstance(f, dict):
                f = [f[k] for k in sorted(f.keys())]
            elif isinstance(f, (list, tuple)):
                f = list(f)
        except Exception as e:
            print(f'[WARN] feature extraction failed for {u}: {e}')
            f = None
        feats.append(f)
    # infer length
    inferred = None
    for f in feats:
        if f is not None:
            inferred = len(f)
            break
    if inferred is None:
        inferred = 16
    feats = [f if f is not None else [0]*inferred for f in feats]
    return feats


def main():
    urls, labels = load_sample(1000)
    print('Loaded sample:', len(urls))
    X = extract_features(urls)
    X = pd.DataFrame(X)
    y = np.array(labels)
    print('Feature matrix shape:', X.shape)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
    print('Train shape:', X_train.shape, 'Test shape:', X_test.shape)

    try:
        from xgboost import XGBClassifier
    except Exception as e:
        print('XGBoost import failed:', e)
        return

    # compute scale_pos_weight
    pos = sum(y_train==1)
    neg = sum(y_train==0)
    spw = neg/pos if pos>0 else 1
    clf = XGBClassifier(use_label_encoder=False, eval_metric='logloss', n_estimators=200, max_depth=5, scale_pos_weight=spw, random_state=42)
    print('Training XGBoost on original features (may take a while)...')
    clf.fit(X_train, y_train)

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

    # save
    try:
        booster = clf.get_booster()
        booster.save_model(OUT_JSON)
        print('Saved JSON model to', OUT_JSON)
    except Exception as e:
        print('Failed to save booster JSON:', e)
    try:
        joblib.dump(clf, OUT_JOBLIB)
        print('Saved joblib model to', OUT_JOBLIB)
    except Exception as e:
        print('Failed to save joblib:', e)

if __name__ == '__main__':
    main()
