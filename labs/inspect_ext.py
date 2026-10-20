import json

with open('data/external_corpus.json', 'r', encoding='utf-8') as f:
    e = json.load(f)

for i in range(0, min(10, len(e)), 2):
    p1 = e[i]
    p2 = e[i+1]
    print(f"[{i}] id={p1['id']}, pos={p1['positive']}, cve={p1.get('cve_id')}")
    print(f"[{i+1}] id={p2['id']}, pos={p2['positive']}, cve={p2.get('cve_id')}")
    print("--- Code 1 ---")
    print(p1['source'])
    print("--- Code 2 ---")
    print(p2['source'])
    print("=" * 50)
