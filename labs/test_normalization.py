import json
import re
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
with open('data/holdout.json', 'r', encoding='utf-8') as f:
    h = json.load(f)

def normalize_code(code: str) -> str:
    # Remove comments
    code = re.sub(r'//.*', '', code)
    code = re.sub(r'/\*[\s\S]*?\*/', '', code)
    
    # Identify dangerous concatenation with user input
    has_taint = bool(re.search(r'\b(req\.(body|query|params|headers|files)|request\.(args|form|values)|input|payload)\b', code))
    has_concat = bool(re.search(r'(\+\s*req|\+\s*input|\$\{\s*req|\$\{\s*input|\bconcat\()', code))
    has_sql = bool(re.search(r'\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b', code, re.IGNORECASE))
    has_param = bool(re.search(r'(\?|\$\d+|:\w+|\[.*req\.)', code))
    has_dom_sink = bool(re.search(r'\b(innerHTML|outerHTML|document\.write)\b', code))
    has_safe_dom = bool(re.search(r'\b(textContent|innerText)\b', code))
    has_file_sink = bool(re.search(r'\b(writeFile|readFile|createReadStream)\b', code))
    has_path_sanitizer = bool(re.search(r'\b(basename|resolve|normalize)\b', code))
    has_eval_sink = bool(re.search(r'\b(eval|Function|exec|spawn)\b', code))
    
    features = []
    if has_taint: features.append("FEATURE_TAINT")
    if has_concat: features.append("FEATURE_CONCAT")
    if has_sql: features.append("FEATURE_SQL")
    if has_param: features.append("FEATURE_PARAMETRIZED")
    if has_dom_sink: features.append("FEATURE_DOM_SINK")
    if has_safe_dom: features.append("FEATURE_SAFE_DOM")
    if has_file_sink: features.append("FEATURE_FILE_SINK")
    if has_path_sanitizer: features.append("FEATURE_PATH_SANITIZER")
    if has_eval_sink: features.append("FEATURE_EVAL_SINK")
    
    # Also keep the tokens
    return " ".join(features) + " " + code

X_c = [normalize_code(x['source']) for x in c]
y_c = [1 if x['positive'] else 0 for x in c]

X_e = [normalize_code(x['source']) for x in e]
y_e = [1 if x['positive'] else 0 for x in e]

X_h = [normalize_code(x['source']) for x in h]
y_h = [1 if x['positive'] else 0 for x in h]

X_train = np.array(X_c + X_e)
y_train = np.array(y_c + y_e)

pipe = Pipeline([
    ("tfidf", TfidfVectorizer(ngram_range=(1, 2), token_pattern=r'(?u)\b\w+\b|[^\w\s]', min_df=1, sublinear_tf=True)),
    ("clf", RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42, class_weight='balanced'))
])

skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
aucs, f1s = [], []
for t, v in skf.split(X_train, y_train):
    pipe.fit(X_train[t], y_train[t])
    probs = pipe.predict_proba(X_train[v])[:, 1]
    preds = pipe.predict(X_train[v])
    aucs.append(roc_auc_score(y_train[v], probs))
    f1s.append(f1_score(y_train[v], preds, zero_division=0))

pipe.fit(X_train, y_train)
h_probs = pipe.predict_proba(X_h)[:, 1]
h_preds = pipe.predict(X_h)

print(f"Normalized CV AUC: {np.mean(aucs):.4f} | CV F1: {np.mean(f1s):.4f}")
print(f"Holdout AUC: {roc_auc_score(y_h, h_probs):.4f} | Holdout F1: {f1_score(y_h, h_preds):.4f}")
