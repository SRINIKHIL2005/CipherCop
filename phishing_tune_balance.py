import os
import sys
import time
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

ROOT = os.path.join(os.path.dirname(__file__), 'Phishing_ML', 'Phishing-Website-Detection-by-Machine-Learning-Techniques')
PHISHING_CSV = os.path.join(ROOT, 'DataFiles', '4.phishing.csv')
LEGIT_CSV = os.path.join(ROOT, 'DataFiles', '3.legitimate.csv')
OUT_JSON = os.path.join(ROOT, 'XGBoostClassifier_tuned_balanced.json')
OUT_JOBLIB = os.path.join(ROOT, 'Phishing_XGB_Model_tuned_balanced.joblib')
THRESH_CSV = os.path.join(ROOT, '..', '..', 'logs', 'threshold_sweep_tuned_balanced.csv')

sys.path.append(os.path.abspath(ROOT))
from URLFeatureExtraction import featureExtraction as project_feature_extraction


def load_rows(csv_path, label):
    df = pd.read_csv(csv_path, header=None)
    urls = df.iloc[:, 0].astype(str).tolist()
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


def threshold_sweep(y_true, probs, out_csv=None):
    results = []
    thresholds = list(np.linspace(0.01, 0.99, 99))
    for t in thresholds:
        preds = (probs >= t).astype(int)
        acc = accuracy_score(y_true, preds)
        prec = precision_score(y_true, preds, zero_division=0)
        rec = recall_score(y_true, preds, zero_division=0)
        f1 = f1_score(y_true, preds, zero_division=0)
        cm = confusion_matrix(y_true, preds)
        results.append({'threshold': t, 'accuracy': acc, 'precision': prec, 'recall': rec, 'f1': f1, 'tn': int(cm[0,0]), 'fp': int(cm[0,1]), 'fn': int(cm[1,0]), 'tp': int(cm[1,1])})
    df = pd.DataFrame(results)
    if out_csv:
        os.makedirs(os.path.dirname(out_csv), exist_ok=True)
        df.to_csv(out_csv, index=False)
    # pick threshold max f1 then max recall as tie-breaker
    best = df.sort_values(['f1', 'recall'], ascending=[False, False]).iloc[0]
    return df, best.to_dict()


def main():
    pos = load_rows(PHISHING_CSV, 1)
    neg = load_rows(LEGIT_CSV, 0)
    data = pos + neg
    urls, labels = zip(*data)
    print('Extracting features for', len(urls), 'rows...')
    X = extract_features(urls)
    X = pd.DataFrame(X)
    y = np.array(labels)

    # split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
    print('Train shape:', X_train.shape, 'Test shape:', X_test.shape)

    try:
        from xgboost import XGBClassifier
    except Exception as e:
        print('XGBoost import failed:', e)
        return

    # compute scale_pos_weight
    pos_count = int((y_train == 1).sum())
    neg_count = int((y_train == 0).sum())
    spw_default = neg_count / pos_count if pos_count > 0 else 1

    base_clf = XGBClassifier(use_label_encoder=False, eval_metric='logloss', random_state=42)

    param_dist = {
        'n_estimators': [100, 200, 300, 400],
        'max_depth': [3, 4, 5, 6],
        'learning_rate': [0.01, 0.03, 0.05, 0.1],
        'subsample': [0.6, 0.7, 0.8, 0.9, 1.0],
        'colsample_bytree': [0.6, 0.7, 0.8, 0.9, 1.0],
        'scale_pos_weight': [1, 2, 4, int(spw_default)]
    }

    n_iter = 36
    print('Starting RandomizedSearchCV (scoring=f1): n_iter=', n_iter)
    rs = RandomizedSearchCV(base_clf, param_distributions=param_dist, n_iter=n_iter, scoring='f1', cv=3, n_jobs=-1, verbose=2, random_state=42, refit=True)

    start = time.time()
    rs.fit(X_train, y_train)
    duration = time.time() - start
    print('Search done in %.1f seconds' % duration)
    print('Best params:', rs.best_params_)
    print('Best CV score (f1):', rs.best_score_)

    best = rs.best_estimator_

    # evaluate on holdout
    probs = best.predict_proba(X_test)[:, 1]
    # threshold sweep
    df_thresh, best_thresh = threshold_sweep(y_test, probs, out_csv=THRESH_CSV)
    print('Best threshold by F1:', best_thresh)

    # evaluate at recommended threshold
    t = float(best_thresh['threshold'])
    preds = (probs >= t).astype(int)
    acc = accuracy_score(y_test, preds)
    prec = precision_score(y_test, preds, zero_division=0)
    rec = recall_score(y_test, preds, zero_division=0)
    f1v = f1_score(y_test, preds, zero_division=0)
    cm = confusion_matrix(y_test, preds)
    print('Holdout evaluation at threshold %.3f:' % t)
    print(' Accuracy:', acc)
    print(' Precision:', prec)
    print(' Recall:', rec)
    print(' F1:', f1v)
    print(' Confusion matrix:\n', cm)

    # save artifacts
    try:
        booster = best.get_booster()
        booster.save_model(OUT_JSON)
        print('Saved JSON model to', OUT_JSON)
    except Exception as e:
        print('Failed to save booster JSON:', e)
    try:
        joblib.dump(best, OUT_JOBLIB)
        print('Saved joblib model to', OUT_JOBLIB)
    except Exception as e:
        print('Failed to save joblib:', e)

    print('Threshold sweep saved to', THRESH_CSV)
    print('Done')


if __name__ == '__main__':
    main()
