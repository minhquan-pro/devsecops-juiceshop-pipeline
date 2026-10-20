import json
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import roc_auc_score, f1_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression

with open('data/corpus.json', 'r', encoding='utf-8') as f:
    c = json.load(f)
with open('data/external_corpus.json', 'r', encoding='utf-8') as f:
    e = json.load(f)

X_c = [x['source'] for x in c]
y_c = [1 if x['positive'] else 0 for x in c]

X_e = [x['source'] for x in e]
y_e = [1 if x['positive'] else 0 for x in e]

pipe = Pipeline([
    ("features", FeatureUnion([
        ("char_wb", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), max_features=3500, sublinear_tf=True)),
        ("token_words", TfidfVectorizer(analyzer="word", ngram_range=(1, 2), max_features=2000, sublinear_tf=True))
    ])),
    ("clf", RandomForestClassifier(n_estimators=120, max_depth=18, random_state=42, class_weight="balanced"))
])

# Test on Corpus CV alone
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
aucs_c = []
for t, v in skf.split(X_c, y_c):
    pipe.fit(np.array(X_c)[t], np.array(y_c)[t])
    p = pipe.predict_proba(np.array(X_c)[v])[:, 1]
    aucs_c.append(roc_auc_score(np.array(y_c)[v], p))
print(f"Corpus only 5-Fold CV AUC: {np.mean(aucs_c):.4f}")

# Test on External CV alone
aucs_e = []
for t, v in skf.split(X_e, y_e):
    pipe.fit(np.array(X_e)[t], np.array(y_e)[t])
    p = pipe.predict_proba(np.array(X_e)[v])[:, 1]
    aucs_e.append(roc_auc_score(np.array(y_e)[v], p))
print(f"External only 5-Fold CV AUC: {np.mean(aucs_e):.4f}")

# Train on Corpus, Test on External
pipe.fit(X_c, y_c)
p_e = pipe.predict_proba(X_e)[:, 1]
print(f"Train on Corpus, Test on External AUC: {roc_auc_score(y_e, p_e):.4f}")

# Train on External, Test on Corpus
pipe.fit(X_e, y_e)
p_c = pipe.predict_proba(X_c)[:, 1]
print(f"Train on External, Test on Corpus AUC: {roc_auc_score(y_c, p_c):.4f}")
