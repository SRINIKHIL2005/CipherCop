import os
import sys
import subprocess

log_path = os.path.join(os.path.dirname(__file__), 'logs', 'phishing_threshold_sweep.log')
os.makedirs(os.path.dirname(log_path), exist_ok=True)
script_path = os.path.join(os.path.dirname(__file__), 'phishing_threshold_sweep.py')
res = subprocess.run([sys.executable, script_path], capture_output=True, text=True)
out = ''
if res.stdout:
    out += res.stdout
if res.stderr:
    out += '\n--- STDERR ---\n' + res.stderr
with open(log_path, 'w', encoding='utf-8') as f:
    f.write(out)
print('Wrote log to', log_path)
