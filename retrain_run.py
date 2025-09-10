import subprocess
import sys, os
log = os.path.join(os.path.dirname(__file__), 'logs', 'retrain.log')
os.makedirs(os.path.dirname(log), exist_ok=True)
try:
    res = subprocess.run([sys.executable, os.path.join(os.path.dirname(__file__), 'phishing_retrain_current_extractor.py')], capture_output=True, text=True)
    out = ''
    if res.stdout:
        out += res.stdout
    if res.stderr:
        out += '\n--- STDERR ---\n' + res.stderr
except Exception as e:
    out = 'ERROR running retrain: ' + str(e)
with open(log, 'w', encoding='utf-8') as f:
    f.write(out)
print('Wrote', log)
