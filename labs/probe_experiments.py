import json
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import roc_auc_score, f1_score, accuracy_score
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_selection import SelectPercentile, SelectKBest, chi2

def load(p):
    with open(p, 'r', encoding='utf-8') as f:
        d = json.load(f)
    return [i.get('source') or i.get('code', '') for i in d], [1 if i.get('positive') or i.get('label') in [1, True, '1'] else 0 for i in d]

X_c, y_c = load('data/corpus.json')
X_e, y_e = load('data/external_corpus.json')
X_h, y_h = load('data/holdout.json')

X_train = np.array(X_c + X_e)
y_train = np.array(y_c + y_e)
X_holdout = np.array(X_h)
y_holdout = np.array(y_h)

print(f"Train samples: {len(X_train)}, Holdout samples: {len(X_holdout)}")

skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

experiments = [
    (
        "Original RF(120)",
        Pipeline([
            ("features", FeatureUnion([
                ("char_wb", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), max_features=3500, sublinear_tf=True)),
                ("token_words", TfidfVectorizer(analyzer="word", ngram_range=(1, 2), token_pattern=r"(?u)\b\w+\b|[^\w\s]", max_features=2000, sublinear_tf=True))
            ])),
            ("clf", RandomForestClassifier(n_estimators=120, max_depth=18, random_state=42, class_weight="balanced"))
        ])
    ),
    (
        "TFIDF (word 1-2, char 3-5) + LinearSVC (Calibrated)",
        Pipeline([
            ("features", FeatureUnion([
                ("char_wb", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, max_features=800, sublinear_tf=True)),
                ("token_words", TfidfVectorizer(analyzer="word", ngram_range=(1, 2), min_df=2, max_features=500, sublinear_tf=True))
            ])),
            ("clf", CalibratedClassifierCV(LinearSVC(C=1.0, random_state=42, class_weight="balanced"), cv=3))
        ])
    ),
    (
        "TFIDF Word + Char + LogisticRegression L2 (C=1.0)",
        Pipeline([
            ("features", FeatureUnion([
                ("char_wb", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, max_features=1000, sublinear_tf=True)),
                ("token_words", TfidfVectorizer(analyzer="word", ngram_range=(1, 2), min_df=2, max_features=600, sublinear_tf=True))
            ])),
            ("clf", CalibratedClassifierCV(LogisticRegression(C=1.0, penalty="l2", solver="liblinear", random_state=42, class_weight="balanced"), cv=3))
        ])
    ),
    (
        "Feature Selection (chi2 top 300) + RF(depth=8)",
        Pipeline([
            ("features", FeatureUnion([
                ("char_wb", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, sublinear_tf=True)),
                ("token_words", TfidfVectorizer(analyzer="word", ngram_range=(1, 2), min_df=2, sublinear_tf=True))
            ])),
            ("select", SelectKBest(score_func=chi2, k=250)),
            ("clf", CalibratedClassifierCV(LogisticRegression(C=2.0, penalty="l2", solver="liblinear", random_state=42, class_weight="balanced"), cv=3))
        ])
    ),
]

for name, pipe in experiments:
    cv_aucs, cv_f1s = [], []
    for train_idx, val_idx in skf.split(X_train, y_train):
        pipe.fit(X_train[train_idx], y_train[train_idx])
        probs = pipe.predict_proba(X_train[val_idx])[:, 1]
        preds = pipe.predict(X_train[val_idx])
        cv_aucs.append(roc_auc_score(y_train[val_idx], probs))
        cv_f1s.append(f1_score(y_train[val_idx], preds, zero_division=0))
    
    pipe.fit(X_train, y_train)
    h_probs = pipe.predict_proba(X_holdout)[:, 1]
    h_preds = pipe.predict(X_holdout)
    h_auc = roc_auc_score(y_holdout, h_probs)
    h_f1 = f1_score(y_holdout, h_preds, zero_division=0)
    
    print(f"{name:50s} | CV AUC: {np.mean(cv_aucs):.4f} | CV F1: {np.mean(cv_f1s):.4f} | Holdout AUC: {h_auc:.4f} | Holdout F1: {h_f1:.4f}")
