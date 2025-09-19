# Quick import check for backend app
import importlib
m = importlib.import_module('app')
print('import ok')
print('ml_model_loaded:', getattr(m, 'ml_model', None) is not None)
print('ml_model_type:', type(getattr(m, 'ml_model', None)).__name__ if getattr(m, 'ml_model', None) else None)
print('ML_THRESHOLD:', getattr(m, 'ML_THRESHOLD', None))
print('XGBOOST_JSON_PATH:', getattr(m, 'XGBOOST_JSON_PATH', None))
# Try a sample prediction if model and feature extractor are available
try:
    feats = m.featureExtraction('http://example.com')
    norm = m.normalize_features_for_model(feats, m.ml_model)
    proba = None
    if getattr(m, 'ml_model', None) is not None:
        mdl = m.ml_model
        if hasattr(mdl, 'predict_proba'):
            proba = mdl.predict_proba([norm])
        elif hasattr(mdl, 'predict'):
            pred = mdl.predict([norm])
            proba = [[1-pred[0], pred[0]]]
    print('sample_features:', norm)
    print('sample_proba:', proba)
except Exception as e:
    print('sample prediction failed:', e)
