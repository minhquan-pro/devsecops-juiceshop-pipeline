import json
import re
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.metrics import roc_auc_score, f1_score, accuracy_score, precision_score, recall_score, brier_score_loss
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
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
            has_eval_sink = 1.0 if re.search(r'\b(eval|Function|exec|spawn|execSync|spawnSync|child_process)\b', code_clean) and not re.search(r'\bliteral_eval\b', code_clean) else 0.0
            has_file_sink = 1.0 if re.search(r'\b(writeFile|readFile|createReadStream|createWriteStream|open)\b', code_clean) else 0.0
            has_proto_sink = 1.0 if re.search(r'\b(merge|extend|cloneDeep|__proto__|constructor\.prototype)\b', code_clean) else 0.0
            has_tmpl_sink = 1.0 if re.search(r'\b(template|compile|render)\b', code_clean) else 0.0
            has_nosql_sink = 1.0 if re.search(r'\b(\$where|\$regex|\$gt|\$ne)\b', code_clean) else 0.0
            has_crypto_sink = 1.0 if re.search(r'\b(md5|sha1|DES|createCipher)\b', code_clean, re.I) else 0.0
            has_yaml_sink = 1.0 if re.search(r'\byaml\.load\b', code_clean) and not re.search(r'\bsafe_load\b', code_clean) else 0.0
            has_xml_sink = 1.0 if re.search(r'\b(parseString|fromstring|etree)\b', code_clean) and not re.search(r'\bdefusedxml\b', code_clean) else 0.0
            has_ssrf_sink = 1.0 if re.search(r'\b(urllib\.request|urllib2|requests\.get|http\.get|fetch)\b', code_clean) else 0.0
            has_csrf_risk = 1.0 if re.search(r'\b(router\.get|\.get\().*(change|update|delete|transfer|edit)', code_clean, re.I) else 0.0

            # Sources
            has_source = 1.0 if re.search(r'\b(req\.(body|query|params|headers|files)|request\.(args|form|values|GET|POST)|user_input|payload|input|location\.hash)\b', code_clean) else 0.0

            # Dangerous Concat / Interpolation
            has_concat = 1.0 if re.search(r'(\+\s*(req\.|input|payload|raw_input)|\$\{\s*(req\.|input|payload|raw_input)|\bjoin\(.*req\.)', code_clean) else 0.0
            sql_concat = 1.0 if (has_sql_kw or has_sql_sink) and (has_concat or has_source) else 0.0
            dom_concat = 1.0 if has_dom_sink and (has_concat or has_source) else 0.0
            file_concat = 1.0 if has_file_sink and (has_concat or has_source) else 0.0
            eval_source = 1.0 if has_eval_sink and (has_source or has_concat) else 0.0
            ssrf_source = 1.0 if has_ssrf_sink and (has_source or has_concat) else 0.0

            # Safe / Sanitizer patterns
            has_param = 1.0 if re.search(r'(\?|\$\d+|:\w+|\[\s*(req\.|user|input)|\.execute\(.*,\s*\[|\.execute\(.*,\s*\()', code_clean) else 0.0
            has_safe_dom = 1.0 if re.search(r'\b(textContent|innerText)\b', code_clean) else 0.0
            has_path_safe = 1.0 if re.search(r'\b(path\.basename|path\.resolve|os\.path\.basename|os\.path\.abspath|basename)\b', code_clean) and not has_concat else 0.0
            has_safe_yaml = 1.0 if re.search(r'\b(safe_load|SafeLoader)\b', code_clean) else 0.0
            has_safe_xml = 1.0 if re.search(r'\b(defusedxml|resolve_entities=False)\b', code_clean) else 0.0
            has_safe_eval = 1.0 if re.search(r'\b(literal_eval)\b', code_clean) else 0.0
            has_validate = 1.0 if re.search(r'\b(validator|escape|encodeURIComponent|sanitize|safe|allowedKeys|whitelist|check_csrf)\b', code_clean, re.I) else 0.0
            is_pure_comment = 1.0 if len(code_lines) == 0 else 0.0

            # High-confidence positive indicator
            is_definitely_vuln = 1.0 if (
                (sql_concat and not has_param) or
                (dom_concat and not has_safe_dom) or
                (file_concat and not has_path_safe) or
                eval_source or
                has_yaml_sink or
                has_xml_sink or
                ssrf_source or
                has_csrf_risk
            ) else 0.0

            # High-confidence safe indicator
            is_definitely_safe = 1.0 if (
                has_param or has_safe_dom or has_path_safe or has_safe_yaml or
                has_safe_xml or has_safe_eval or is_pure_comment
            ) else 0.0

            features.append([
                has_sql_kw, has_sql_sink, has_dom_sink, has_eval_sink, has_file_sink, has_proto_sink, has_tmpl_sink, has_nosql_sink, has_crypto_sink,
                has_yaml_sink, has_xml_sink, has_ssrf_sink, has_csrf_risk,
                has_source, has_concat, sql_concat, dom_concat, file_concat, eval_source, ssrf_source,
                has_param, has_safe_dom, has_path_safe, has_safe_yaml, has_safe_xml, has_safe_eval, has_validate, is_pure_comment,
                is_definitely_vuln, is_definitely_safe
            ])
        return csr_matrix(features)

groups = []
items = []
for item in c:
    item_id = item['id']
    num = int(''.join(filter(str.isdigit, item_id)) or '0')
    prefix = item_id[:3]
    groups.append(f"{prefix}_{(num + 1) // 2}")
    items.append(item)

for item in e:
    cve = item.get('cve_id', '')
    base_cve = cve.replace('-FIX', '')
    groups.append(base_cve)
    items.append(item)

groups = np.array(groups)
X_train = [x['source'] for x in items]
y_train = np.array([1 if x['positive'] else 0 for x in items])

X_h = [x['source'] for x in h]
y_h = np.array([1 if x['positive'] else 0 for x in h])

voting_clf = VotingClassifier(
    estimators=[
        ('lr', LogisticRegression(C=2.5, random_state=42, class_weight='balanced', solver='liblinear')),
        ('rf', RandomForestClassifier(n_estimators=100, max_depth=8, random_state=42, class_weight='balanced'))
    ],
    voting='soft',
    weights=[1.5, 1.0]
)

calibrated_clf = CalibratedClassifierCV(voting_clf, cv=3)

pipe = Pipeline([
    ("features", FeatureUnion([
        ("tfidf_token", TfidfVectorizer(ngram_range=(1, 2), token_pattern=r"(?u)\b\w+\b|[^\w\s]", min_df=1, sublinear_tf=True)),
        ("domain", SecurityFeatureExtractor())
    ])),
    ("clf", calibrated_clf)
])

sgkf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
aucs, f1s, accs = [], [], []
for t, v in sgkf.split(X_train, y_train, groups=groups):
    pipe.fit([X_train[i] for i in t], y_train[t])
    probs = pipe.predict_proba([X_train[i] for i in v])[:, 1]
    preds = pipe.predict([X_train[i] for i in v])
    aucs.append(roc_auc_score(y_train[v], probs))
    f1s.append(f1_score(y_train[v], preds, zero_division=0))
    accs.append(accuracy_score(y_train[v], preds))

pipe.fit(X_train, y_train)
h_probs = pipe.predict_proba(X_h)[:, 1]
h_preds = pipe.predict(X_h)
brier = brier_score_loss(y_h, h_probs)

print(f"Calibrated Voting | G-CV AUC: {np.mean(aucs):.4f} | F1: {np.mean(f1s):.4f} | Acc: {np.mean(accs):.4f}")
print(f"Holdout AUC: {roc_auc_score(y_h, h_probs):.4f} | F1: {f1_score(y_h, h_preds):.4f} | Acc: {accuracy_score(y_h, h_preds):.4f} | Brier: {brier:.4f}")
