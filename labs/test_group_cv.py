import json
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.model_selection import GroupKFold, StratifiedGroupKFold
from sklearn.metrics import roc_auc_score, f1_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression

with open('data/corpus.json', 'r', encoding='utf-8') as f:
    c = json.load(f)
with open('data/external_corpus.json', 'r', encoding='utf-8') as f:
    e = json.load(f)
with open('data/holdout.json', 'r', encoding='utf-8') as f:
    h = json.load(f)

# Build groups for corpus (e.g. SQL01 & SQL02 share group SQL_01)
groups_c = []
for item in c:
    item_id = item['id']
    # e.g. SQL01 -> SQL, or group by every 2 items
    prefix = item_id[:3]
    # pair index
    num = int(''.join(filter(str.isdigit, item_id)) or '0')
    pair_id = f"{prefix}_{(num + 1)//2}"
    groups_c.append(pair_id)

# Build groups for external
groups_e = []
for item in e:
    cve = item.get('cve_id', '')
    base_cve = cve.replace('-FIX', '')
    groups_e.append(base_cve)

groups_train = np.array(groups_c + groups_e)
X_train = np.array([x['source'] for x in c] + [x['source'] for x in e])
y_train = np.array([1 if x['positive'] else 0 for x in c] + [1 if x['positive'] else 0 for x in e])

X_h = np.array([x['source'] for x in h])
y_h = np.array([1 if x['positive'] else 0 for x in h])

print(f"Total train: {len(X_train)}, Unique groups: {len(set(groups_train))}")

sgkf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)

for name, clf in [
    ("RF(depth=12, n=100)", RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42, class_weight='balanced')),
    ("LogReg(C=1.0)", LogisticRegression(C=1.0, random_state=42, class_weight='balanced', solver='liblinear')),
    ("LogReg(C=2.0)", LogisticRegression(C=2.0, random_state=42, class_weight='balanced', solver='liblinear')),
]:
    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 3), token_pattern=r'(?u)\b\w+\b|[^\w\s]', min_df=1, sublinear_tf=True)),
        ("clf", clf)
    ])
    
    aucs, f1s = [], []
    for t, v in sgkf.split(X_train, y_train, groups=groups_train):
        pipe.fit(X_train[t], y_train[t])
        probs = pipe.predict_proba(X_train[v])[:, 1]
        preds = pipe.predict(X_train[v])
        aucs.append(roc_auc_score(y_train[v], probs))
        f1s.append(f1_score(y_train[v], preds, zero_division=0))
    
    pipe.fit(X_train, y_train)
    h_probs = pipe.predict_proba(X_h)[:, 1]
    h_preds = pipe.predict(X_h)
    
    print(f"{name:25s} | GroupCV AUC: {np.mean(aucs):.4f} | GroupCV F1: {np.mean(f1s):.4f} | Holdout AUC: {roc_auc_score(y_h, h_probs):.4f} | Holdout F1: {f1_score(y_h, h_preds):.4f}")
