import json
import numpy as np

with open('data/corpus.json', 'r', encoding='utf-8') as f:
    c = json.load(f)
with open('data/external_corpus.json', 'r', encoding='utf-8') as f:
    e = json.load(f)
with open('data/holdout.json', 'r', encoding='utf-8') as f:
    h = json.load(f)

print(f"Corpus: {len(c)} items, positive count: {sum(1 for x in c if x.get('positive'))}")
print(f"External: {len(e)} items, positive count: {sum(1 for x in e if x.get('positive'))}")
print(f"Holdout: {len(h)} items, positive count: {sum(1 for x in h if x.get('positive'))}")

# Look at labels in external_corpus.json
for idx, x in enumerate(e[:10]):
    print(f"E[{idx}] id={x.get('id')}, positive={x.get('positive')}, label={x.get('label')}")
