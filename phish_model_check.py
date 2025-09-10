import joblib, os, sys
MODEL = os.path.join(os.path.dirname(__file__), 'Phishing_ML', 'Phishing-Website-Detection-by-Machine-Learning-Techniques', 'Phishing_XGB_Model_tuned_balanced.joblib')
print('MODEL PATH:', MODEL)
if not os.path.exists(MODEL):
    print('Model not found')
    sys.exit(2)
mdl = joblib.load(MODEL)
print('Loaded type:', type(mdl))
print('Has predict:', hasattr(mdl, 'predict'))
print('Has predict_proba:', hasattr(mdl, 'predict_proba'))
try:
    # Try a tiny fake input depending on expected n_features_in_
    n = getattr(mdl, 'n_features_in_', 16) or 16
    print('n_features_in_:', n)
    sample = [[0]*int(n)]
    if hasattr(mdl, 'predict_proba'):
        print('predict_proba sample:', mdl.predict_proba(sample)[:1])
    else:
        print('predict sample:', mdl.predict(sample)[:1])
except Exception as e:
    import traceback
    print('ERROR loading or predicting:', e)
    traceback.print_exc()
    sys.exit(1)
