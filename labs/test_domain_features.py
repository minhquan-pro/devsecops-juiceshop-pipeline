import json
import re
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.model_selection import StratifiedGroupKFold, StratifiedKFold
from sklearn.metrics import roc_auc_score, f1_score, accuracy_score, brier_score_loss
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, HistGradientBoostingClassifier, ExtraTreesClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from scipy.sparse import csr_matrix

with open('data/corpus.json', 'r', encoding='utf-8') as f:
    c = json.load(f)
with open('data/external_corpus.json', 'r', encoding='utf-8') as f:
    e = json.load(f)
with open('data/holdout.json', 'r', encoding='utf-8') as f:
    h = json.load(f)

class SecurityFeatureExtractor(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None):
        return self

    def transform(self, X):
        features = []
        for text in X:
            lines = [l.strip() for l in text.splitlines() if l.strip()]
            code_lines = [l for l in lines if not l.startswith('//') and not l.startswith('/*') and not l.startswith('*')]
            code_clean = "\n".join(code_lines)
            
            # Sinks
            has_sql_kw = 1.0 if re.search(r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b', code_clean, re.I) else 0.0
            has_sql_sink = 1.0 if re.search(r'\b(db\.query|db\.execute|query|execute)\b', code_clean) else 0.0
            has_dom_sink = 1.0 if re.search(r'\b(innerHTML|outerHTML|document\.write)\b', code_clean) else 0.0
            has_eval_sink = 1.0 if re.search(r'\b(eval|Function|exec|spawn|execSync)\b', code_clean) else 0.0
            has_file_sink = 1.0 if re.search(r'\b(writeFile|readFile|createReadStream|createWriteStream)\b', code_clean) else 0.0
            has_proto_sink = 1.0 if re.search(r'\b(merge|extend|cloneDeep|__proto__|constructor\.prototype)\b', code_clean) else 0.0
            has_tmpl_sink = 1.0 if re.search(r'\b(template|compile|render)\b', code_clean) else 0.0
            has_nosql_sink = 1.0 if re.search(r'\b(\$where|\$regex|\$gt|\$ne)\b', code_clean) else 0.0

            # Sources
            has_source = 1.0 if re.search(r'\b(req\.(body|query|params|headers|files)|request\.(args|form|values)|user_input|payload|input)\b', code_clean) else 0.0

            # Dangerous Concat / Interpolation
            has_concat = 1.0 if re.search(r'(\+\s*(req\.|input|payload)|\$\{\s*(req\.|input|payload))', code_clean) else 0.0
            sql_concat = 1.0 if (has_sql_kw or has_sql_sink) and (has_concat or has_source) else 0.0
            dom_concat = 1.0 if has_dom_sink and (has_concat or has_source) else 0.0
            file_concat = 1.0 if has_file_sink and (has_concat or has_source) else 0.0
            eval_source = 1.0 if has_eval_sink and (has_source or has_concat) else 0.0

            # Safe / Sanitizer patterns
            has_param = 1.0 if re.search(r'(\?|\$\d+|:\w+|\[\s*(req\.|user|input))', code_clean) else 0.0
            has_safe_dom = 1.0 if re.search(r'\b(textContent|innerText)\b', code_clean) else 0.0
            has_path_safe = 1.0 if re.search(r'\b(path\.basename|path\.join|basename)\b', code_clean) and not has_concat else 0.0
            has_validate = 1.0 if re.search(r'\b(validator|escape|encodeURIComponent|sanitize|safe)\b', code_clean, re.I) else 0.0
            is_pure_comment = 1.0 if len(code_lines) == 0 else 0.0

            # Composite vulnerability indicator
            vuln_indicator = 1.0 if (sql_concat and not has_param) or (dom_concat and not has_safe_dom) or (file_concat and not has_path_safe) or eval_source else 0.0

            features.append([
                has_sql_kw, has_sql_sink, has_dom_sink, has_eval_sink, has_file_sink, has_proto_sink, has_tmpl_sink, has_nosql_sink,
                has_source, has_concat, sql_concat, dom_concat, file_concat, eval_source,
                has_param, has_safe_dom, has_path_safe, has_validate, is_pure_comment, vuln_indicator
            ])
        return csr_matrix(features)

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
X_train = [x['source'] for x in c] + [x['source'] for x in e]
y_train = np.array([1 if x['positive'] else 0 for x in c] + [1 if x['positive'] else 0 for x in e])

X_h = [x['source'] for x in h]
y_h = np.array([1 if x['positive'] else 0 for x in h])

classifiers = [
    ("RF(100, d=8)", RandomForestClassifier(n_estimators=100, max_depth=8, random_state=42, class_weight='balanced')),
    ("RF(150, d=10, min_samples_leaf=2)", RandomForestClassifier(n_estimators=150, max_depth=10, min_samples_leaf=2, random_state=42, class_weight='balanced')),
    ("ExtraTrees(100, d=8)", ExtraTreesClassifier(n_estimators=100, max_depth=8, random_state=42, class_weight='balanced')),
    ("GradBoost(n=60, lr=0.08, d=3)", GradientBoostingClassifier(n_estimators=60, learning_rate=0.08, max_depth=3, random_state=42)),
    ("Calibrated LogReg(C=2.0)", CalibratedClassifierCV(LogisticRegression(C=2.0, random_state=42, class_weight='balanced', solver='liblinear'), cv=3)),
    ("Calibrated RF(80, d=6)", CalibratedClassifierCV(RandomForestClassifier(n_estimators=80, max_depth=6, random_state=42, class_weight='balanced'), cv=3)),
]

sgkf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)

for clf_name, clf in classifiers:
    pipeline = Pipeline([
        ("features", FeatureUnion([
            ("tfidf_token", TfidfVectorizer(ngram_range=(1, 2), token_pattern=r"(?u)\b\w+\b|[^\w\s]", min_df=1, sublinear_tf=True)),
            ("domain", SecurityFeatureExtractor())
        ])),
        ("clf", clf)
    ])

    aucs, f1s = [], []
    for t, v in sgkf.split(X_train, y_train, groups=groups):
        pipeline.fit([X_train[i] for i in t], y_train[t])
        probs = pipeline.predict_proba([X_train[i] for i in v])[:, 1]
        preds = pipeline.predict([X_train[i] for i in v])
        aucs.append(roc_auc_score(y_train[v], probs))
        f1s.append(f1_score(y_train[v], preds, zero_division=0))

    pipeline.fit(X_train, y_train)
    h_probs = pipeline.predict_proba(X_h)[:, 1]
    h_preds = pipeline.predict(X_h)
    print(f"{clf_name:35s} | G-CV AUC: {np.mean(aucs):.4f} | G-CV F1: {np.mean(f1s):.4f} | Holdout AUC: {roc_auc_score(y_h, h_probs):.4f} | Holdout F1: {f1_score(y_h, h_preds):.4f}")
