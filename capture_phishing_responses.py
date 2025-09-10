import requests
import json

target = 'http://127.0.0.1:5000/analyze/fake-website'
urls = [
    'http://1337x.to/torrent/1110018/Blackhat-2015-RUSSIAN-720p-WEB-DL-DD5-1-H264-RUFGT/',
    'http://example.com/'
]

for u in urls:
    try:
        r = requests.post(target, json={'url': u}, timeout=15)
        print('URL:', u)
        print('STATUS:', r.status_code)
        try:
            print(json.dumps(r.json(), indent=2))
        except Exception:
            print(r.text)
        print('\n' + ('-'*60) + '\n')
    except Exception as e:
        print('ERROR calling', u, e)
