import os
import sys
import pandas as pd
import numpy as np

ROOT = os.path.join(os.path.dirname(__file__), 'Phishing_ML', 'Phishing-Website-Detection-by-Machine-Learning-Techniques')
PHISHING_CSV = os.path.join(ROOT, 'DataFiles', '4.phishing.csv')
XGB_JSON = os.path.join(ROOT, 'XGBoostClassifier.json')

sys.path.append(os.path.abspath(ROOT))
from URLFeatureExtraction import featureExtraction as project_feature_extraction

out_path = os.path.join(os.path.dirname(__file__), 'logs', 'feature_debug.log')
os.makedirs(os.path.dirname(out_path), exist_ok=True)

lines = []

def writeln(s=''):
    lines.append(str(s))

try:
    df_urls = pd.read_csv(PHISHING_CSV, header=None)
    urls = df_urls.iloc[:,0].astype(str).tolist()
    sample_urls = urls[:10]
    writeln(f'Read {len(urls)} URLs, sampling first {len(sample_urls)}')

    feats = []
    for i,u in enumerate(sample_urls):
        try:
            f = project_feature_extraction(u)
            # normalize to list
            if hasattr(f, 'tolist'):
                f = list(f.tolist())
            elif isinstance(f, dict):
                f = [f[k] for k in sorted(f.keys())]
            elif isinstance(f, (list, tuple)):
                f = list(f)
        except Exception as e:
            f = None
            writeln(f'ERR extracting for {u}: {e}')
        feats.append(f)

    # infer length
    inferred_len = None
    for f in feats:
        if f is not None:
            inferred_len = len(f)
            break
    if inferred_len is None:
        inferred_len = 30

    # replace None
    feats = [f if f is not None else [0]*inferred_len for f in feats]

    writeln('\nSample feature vectors (first 10 values shown)')
    for i,(u,f) in enumerate(zip(sample_urls, feats)):
        writeln(f'{i+1:02d}. len={len(f)} var={np.var(f):.6g} first10={f[:10]} url={u}')

    df = pd.DataFrame(feats)
    writeln('\nDataFrame shape: ' + str(df.shape))
    writeln('\nDataFrame head:')
    writeln(df.head().to_string())

    # uniqueness per column
    nunique = df.nunique()
    writeln('\nColumns with >1 unique values:')
    cols_multi = [(i,int(n)) for i,n in enumerate(nunique) if n>1]
    if cols_multi:
        writeln(str(cols_multi[:20]))
    else:
        writeln('NONE — all columns identical across sampled rows')

    # check row-wise uniqueness
    row_unique_counts = df.drop_duplicates().shape[0]
    writeln(f'Unique rows among sample: {row_unique_counts}/{len(df)}')

    # attempt to load XGBoost JSON and predict on these sample features
    try:
        import xgboost as xgb
        b = xgb.Booster()
        b.load_model(XGB_JSON)
        dmat = xgb.DMatrix(df)
        pred = b.predict(dmat)
        writeln('\nXGBoost predictions on sample:')
        writeln(str(list(pred)))
        writeln('pred min/max: ' + str((float(pred.min()), float(pred.max()))))
    except Exception as e:
        writeln('XGBoost predict error: ' + str(e))

except Exception as e:
    writeln('FATAL error: ' + str(e))

with open(out_path, 'w', encoding='utf-8') as f:
    f.write('\n'.join(lines))

print('Wrote debug log to', out_path)
