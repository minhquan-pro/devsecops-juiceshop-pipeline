import json
import re
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.metrics import roc_auc_score, f1_score
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, ExtraTreesClassifier
from sklearn.linear_model import LogisticRegression, RidgeClassifier
from sklearn.calibration import CalibratedClassifierCV

with open('data/corpus.json', 'r', encoding='utf-8') as f:
    c = json.load(f)
with open('data/external_corpus.json', 'r', encoding='utf-8') as f:
    e = json.load(f)
with open('data/holdout.json', 'r', encoding='utf-8') as f:
    h = json.load(f)

# Group definitions:
# In external, group is base CVE
# In corpus, group is category/pair
groups = []
for item in c:
    item_id = item['id']
    num = int(''.join(filter(str.isdigit, item_id)) or '0')
    prefix = item_id[:3]
    groups.append(f"{prefix}_{(num + 1) // 2}")

for item in e:
    cve = item.get('cve_id', '')
    base_cve = cve.replace('-FIX', '')
    groups.append(base_cve)

groups = np.array(groups)
X_train_raw = [x['source'] for x in c] + [x['source'] for x in e]
y_train = np.array([1 if x['positive'] else 0 for x in c] + [1 if x['positive'] else 0 for x in e])

X_h_raw = [x['source'] for x in h]
y_h = np.array([1 if x['positive'] else 0 for x in h])

# Let's inspect tokenizers
# Standard word tokenizer splits on words and symbols
sgkf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)

for name, vec in [
    ("word (1,2) token_pattern", TfidfVectorizer(ngram_range=(1, 2), token_pattern=r"(?u)\b\w+\b|[^\w\s]", min_df=1, sublinear_tf=True)),
    ("word (1,3) token_pattern", TfidfVectorizer(ngram_range=(1, 3), token_pattern=r"(?u)\b\w+\b|[^\w\s]", min_df=1, sublinear_tf=True)),
    ("char_wb (3,5) min_df=2", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, sublinear_tf=True)),
    ("char (2,4) min_df=2", TfidfVectorizer(analyzer="char", ngram_range=(2, 4), min_df=2, sublinear_tf=True)),
]:
    X_train_mat = vec.fit_transform(X_train_raw)
    X_h_mat = vec.transform(X_h_raw)
    
    for clf_name, clf in [
        ("RF(100, d=8)", RandomForestClassifier(n_estimators=100, max_depth=8, random_state=42, class_weight='balanced')),
        ("ExtraTrees(100, d=8)", ExtraTreesClassifier(n_estimators=100, max_depth=8, random_state=42, class_weight='balanced')),
        ("LogReg(C=1.0)", LogisticRegression(C=1.0, random_state=42, class_weight='balanced', solver='liblinear')),
        ("LogReg(C=0.5)", LogisticRegression(C=0.5, random_state=42, class_weight='balanced', solver='liblinear')),
    ]:
        aucs, f1s = [], []
        for t, v in sgkf.split(X_train_raw, y_train, groups=groups):
            X_t = vec.fit_transform([X_train_raw[i] for i in t])
            X_v = vec.transform([X_train_raw[i] for i in v])
            clf.fit(X_t, y_train[t])
            if hasattr(clf, "predict_proba"):
                probs = clf.predict_proba(X_v)[:, 1]
            else:
                probs = clf.decision_function(X_v)
            preds = clf.predict(X_v)
            aucs.append(roc_auc_score(y_train[v], probs))
            f1s.append(f1_score(y_train[v], preds, zero_division=0))
        
        clf.fit(X_train_mat, y_train)
        if hasattr(clf, "predict_proba"):
            h_probs = clf.predict_proba(X_h_mat)[:, 1]
        else:
            h_probs = clf.decision_function(X_h_mat)
        h_preds = clf.predict(X_h_mat)
        print(f"{name:25s} | {clf_name:20s} | G-CV AUC: {np.mean(aucs):.4f} | G-CV F1: {np.mean(f1s):.4f} | Holdout AUC: {roc_auc_score(y_h, h_probs):.4f} | Holdout F1: {f1_score(y_h, h_preds):.4f}")
