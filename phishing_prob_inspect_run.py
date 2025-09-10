import io
import sys
from contextlib import redirect_stdout
import os

log_path = r'f:\temp\phishing_prob_inspect.log'
# ensure directory exists
log_path = os.path.join(os.path.dirname(__file__), 'logs', 'phishing_prob_inspect.log')
os.makedirs(os.path.dirname(log_path), exist_ok=True)

import subprocess

script_path = os.path.join(os.path.dirname(__file__), 'phishing_prob_inspect.py')
try:
    res = subprocess.run([sys.executable, script_path], capture_output=True, text=True, check=False)
    out = ''
    if res.stdout:
        out += res.stdout
    if res.stderr:
        out += '\n--- STDERR ---\n' + res.stderr
except Exception as e:
    out = f'ERROR running subprocess: {e}\n'

with open(log_path, 'w', encoding='utf-8') as f:
    f.write(out)

print('Wrote log to', log_path)
