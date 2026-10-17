#!/usr/bin/env python3
import sys, zipfile, re
sys.stdout.reconfigure(encoding='utf-8')

f = zipfile.ZipFile('.aKetqua/Bao_Cao_Bai_Tap_Lon_window_linux_Juice_Shop.docx')
xml = f.read('word/document.xml').decode('utf-8')
text = re.sub('<[^>]+>', '', xml)
joined = ' '.join(text.split())

print(f"Total chars: {len(joined)}")
print(f"Total words: {len(joined.split())}")
print()

patterns = [
    'F1', 'precision', 'recall', '52', 'corpus', 'holdout',
    'JuiceSec', 'evaluate', 'scan_gate', 'DevSecOps',
    'bandit', 'semgrep', 'gitleaks', 'trivy', 'SAST',
    'pipeline', 'phiên bản 1', 'version 1', '__version__',
    'True Positive', 'True Negative', 'TP=', 'FP=',
]

for p in patterns:
    matches = list(re.finditer(p, joined, re.IGNORECASE))
    print(f"=== '{p}' === ({len(matches)} matches)")
    for m in matches[:2]:
        start = max(0, m.start() - 100)
        end = min(len(joined), m.end() + 150)
        print(f"  ...{joined[start:end]}...")
    print()
