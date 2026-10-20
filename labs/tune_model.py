import json
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.model_selection import StratifiedKFold, StratifiedGroupKFold
from sklearn.metrics import roc_auc_score, f1_score, accuracy_score, brier_score_loss
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_selection import SelectKBest, chi2

with open('data/corpus.json', 'r', encoding='utf-8') as f:
    c = json.load(f)
with open('data/external_corpus.json', 'r', encoding='utf-8') as f:
    e = json.load(f)
with open('data/holdout.json', 'r', encoding='utf-8') as f:
    h = json.load(f)

# Build group IDs
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
X_train = np.array([x['source'] for x in c] + [x['source'] for x in e])
y_train = np.array([1 if x['positive'] else 0 for x in c] + [1 if x['positive'] else 0 for x in e])

X_h = np.array([x['source'] for x in h])
y_h = np.array([1 if x['positive'] else 0 for x in h])

# Let's test various vectorizers and classifiers
configs = [
    (
        "TFIDF (word 1-3, sublinear) + LogisticRegression(C=1.0)",
        Pipeline([
            ("tfidf", TfidfVectorizer(ngram_range=(1, 3), token_pattern=r'(?u)\b\w+\b|[^\w\s]', min_df=1, sublinear_tf=True)),
            ("clf", LogisticRegression(C=1.0, random_state=42, class_weight='balanced', solver='liblinear'))
        ])
    ),
    (
        "TFIDF (word 1-2 + char 3-4) + Calibrated LogisticRegression(C=3.0)",
        Pipeline([
            ("features", FeatureUnion([
                ("char", TfidfVectorizer(analyzer="char", ngram_range=(3, 4), min_df=2, sublinear_tf=True)),
                ("word", TfidfVectorizer(analyzer="word", ngram_range=(1, 2), min_df=1, sublinear_tf=True))
            ])),
            ("clf", CalibratedClassifierCV(LogisticRegression(C=3.0, random_state=42, class_weight='balanced', solver='liblinear'), cv=3))
        ])
    ),
    (
        "TFIDF (word 1-2, min_df=2) + RF(depth=10, min_samples_leaf=2)",
        Pipeline([
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2), token_pattern=r'(?u)\b\w+\b|[^\w\s]', min_df=2, sublinear_tf=True)),
            ("clf", RandomForestClassifier(n_estimators=100, max_depth=10, min_samples_leaf=2, random_state=42, class_weight='balanced'))
        ])
    ),
    (
        "Chi2 Select (k=150) + RF(depth=8)",
        Pipeline([
            ("tfidf", TfidfVectorizer(ngram_range=(1, 3), token_pattern=r'(?u)\b\w+\b|[^\w\s]', min_df=1, sublinear_tf=True)),
            ("select", SelectKBest(score_func=chi2, k=150)),
            ("clf", RandomForestClassifier(n_estimators=100, max_depth=8, random_state=42, class_weight='balanced'))
        ])
    )
]

print("=== EVALUATION WITH StratifiedGroupKFold ===")
sgkf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
for name, pipe in configs:
    aucs, f1s = [], []
    for t, v in sgkf.split(X_train, y_train, groups=groups):
        pipe.fit(X_train[t], y_train[t])
        probs = pipe.predict_proba(X_train[v])[:, 1]
        preds = pipe.predict(X_train[v])
        aucs.append(roc_auc_score(y_train[v], probs))
        f1s.append(f1_score(y_train[v], preds, zero_division=0))
    
    pipe.fit(X_train, y_train)
    h_probs = pipe.predict_proba(X_h)[:, 1]
    h_preds = pipe.predict(X_h)
    print(f"{name:55s} | G-CV AUC: {np.mean(aucs):.4f} | G-CV F1: {np.mean(f1s):.4f} | Holdout AUC: {roc_auc_score(y_h, h_probs):.4f} | Holdout F1: {f1_score(y_h, h_preds):.4f}")
