#!/usr/bin/env python3
"""
labs/train_ai_model.py
Train robust AI vulnerability classification model.
Features:
- Domain AST & Security Feature Fusion (SecurityFeatureExtractor) + Subword/Token TF-IDF.
- Calibrated Soft-Voting Ensemble (Regularized Logistic Regression + Shallow Random Forest).
- Stratified Group K-Fold (5 folds) grouping paired CVE samples to eliminate data leakage.
- Exact McNemar Test vs AST baseline.
- 95% Bootstrap Confidence Intervals (B=1000) & Brier Calibration Score.
- Export production model artifact, SHA-256 checksum, and evidence/ai_benchmark.json.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import sys
import time
from pathlib import Path

import joblib
import numpy as np

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# Fix Windows console UTF-8 output
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    brier_score_loss,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import FeatureUnion, Pipeline

from juicesec.ai_classifier import SecurityFeatureExtractor
from juicesec.core import analyze_source

DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
EVIDENCE_DIR = BASE_DIR / "evidence"


def load_dataset(file_path: Path):
    """Load samples from JSON dataset: {"id", "positive", "source", "rationale"}."""
    if not file_path.exists():
        raise FileNotFoundError(f"Dataset not found: {file_path}")

    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    texts = [item.get("source") or item.get("code", "") for item in data]
    labels = [1 if item.get("positive") or item.get("label") in [1, True, "1"] else 0 for item in data]
    ids = [item.get("id") or item.get("cve_id", "") for item in data]
    raw_items = data
    return texts, labels, ids, raw_items


def calculate_exact_mcnemar(y_true, y_pred_ast, y_pred_ai):
    """Calculates Exact McNemar's Test for paired classifiers (AST Heuristic vs AI)."""
    a = b = c = d = 0
    for yt, ya, ym in zip(y_true, y_pred_ast, y_pred_ai):
        ast_ok = (yt == ya)
        ai_ok = (yt == ym)
        if ast_ok and ai_ok:
            a += 1
        elif ast_ok and not ai_ok:
            b += 1
        elif not ast_ok and ai_ok:
            c += 1
        else:
            d += 1

    n_discordant = b + c
    if n_discordant == 0:
        p_value = 1.0
    else:
        k = min(b, c)
        try:
            from scipy.stats import binom
            p_value = float(min(1.0, 2.0 * binom.cdf(k, n_discordant, 0.5)))
        except ImportError:
            cumulative_prob = sum(math.comb(n_discordant, i) for i in range(k + 1)) / (2 ** n_discordant)
            p_value = float(min(1.0, 2.0 * cumulative_prob))

    return {
        "contingency_table": {
            "a_both_correct": a,
            "b_ast_correct_ai_wrong": b,
            "c_ast_wrong_ai_correct": c,
            "d_both_wrong": d,
        },
        "b": int(b),
        "c": int(c),
        "n_discordant": int(n_discordant),
        "p_value": round(p_value, 6),
        "statistically_significant_0_05": bool(p_value < 0.05),
        "statistically_significant_0_01": bool(p_value < 0.01),
        "interpretation": (
            "AI outperforms AST significantly" if (p_value < 0.05 and c > b)
            else "AST outperforms AI significantly" if (p_value < 0.05 and b > c)
            else "No statistically significant difference between AST and AI"
        ),
        "test_type": "exact_binomial_two_sided",
    }


def create_pipeline() -> Pipeline:
    """
    Tạo Pipeline kết hợp:
    1. FeatureUnion giữa Token TF-IDF và Domain AST SecurityFeatureExtractor.
    2. CalibratedClassifierCV bao bọc VotingClassifier (LogisticRegression C=2.5 + RandomForest max_depth=8).
    """
    voting_ensemble = VotingClassifier(
        estimators=[
            ("lr", LogisticRegression(C=2.5, random_state=42, class_weight="balanced", solver="liblinear")),
            ("rf", RandomForestClassifier(n_estimators=100, max_depth=8, random_state=42, class_weight="balanced")),
        ],
        voting="soft",
        weights=[1.5, 1.0],
    )

    calibrated_ensemble = CalibratedClassifierCV(
        estimator=voting_ensemble,
        method="sigmoid",
        cv=3,
    )

    return Pipeline([
        (
            "features",
            FeatureUnion([
                (
                    "tfidf_token",
                    TfidfVectorizer(
                        ngram_range=(1, 2),
                        token_pattern=r"(?u)\b\w+\b|[^\w\s]",
                        min_df=1,
                        sublinear_tf=True,
                    ),
                ),
                (
                    "domain",
                    SecurityFeatureExtractor(include_code_stats=True),
                ),
            ]),
        ),
        ("clf", calibrated_ensemble),
    ])


def build_cve_groups(corpus_items, external_items) -> np.ndarray:
    """
    Tạo nhóm (group identifiers) để gom các cặp đối nghịch (vulnerable vs fixed)
    của cùng một lỗ hổng vào chung 1 nhóm, triệt tiêu rò rỉ dữ liệu (paired-sample leakage) qua StratifiedGroupKFold.
    """
    groups = []
    # 1. Corpus groups: SQL01/02 -> SQL_1, SQL03/04 -> SQL_2, etc.
    for item in corpus_items:
        item_id = item.get("id", "")
        num = int("".join(filter(str.isdigit, item_id)) or "0")
        prefix = item_id[:3]
        groups.append(f"{prefix}_{(num + 1) // 2}")

    # 2. External corpus groups: CVE-2017-5638 vs CVE-2017-5638-FIX -> CVE-2017-5638
    for item in external_items:
        cve = item.get("cve_id", "") or item.get("id", "")
        base_cve = re.sub(r"[-_](FIX|SAFE|BENIGN|PATCHED|SECURE|MUTATION.*)$", "", cve, flags=re.IGNORECASE)
        groups.append(base_cve)

    return np.array(groups)


def main():
    print("=" * 70)
    print(" [AI-SEC ENGINE] HUAN LUYEN VA DANH GIA MO HINH AI PHAN LOAI LO HONG")
    print("=" * 70)

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

    corpus_file = DATA_DIR / "corpus.json"
    external_file = DATA_DIR / "external_corpus.json"
    holdout_file = DATA_DIR / "holdout.json"

    train_texts_c, train_labels_c, _, raw_c = load_dataset(corpus_file)
    train_texts_e, train_labels_e, _, raw_e = load_dataset(external_file)
    holdout_texts, holdout_labels, holdout_ids, _ = load_dataset(holdout_file)

    X_train = np.array(train_texts_c + train_texts_e)
    y_train = np.array(train_labels_c + train_labels_e)
    groups_train = build_cve_groups(raw_c, raw_e)

    X_holdout = np.array(holdout_texts)
    y_holdout = np.array(holdout_labels)

    print(f"[*] Train set: {len(X_train)} samples across {len(np.unique(groups_train))} CVE groups "
          f"(Vulnerable: {sum(y_train)}, Benign: {len(y_train) - sum(y_train)})")
    print(f"[*] Holdout set: {len(X_holdout)} samples (Vulnerable: {sum(y_holdout)}, Benign: {len(y_holdout) - sum(y_holdout)})")

    # 1. 5-Fold Stratified Group Cross-Validation
    print("\n[+] Running 5-Fold Stratified Group Cross-Validation (Leakage-Proof)...")
    sgkf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)

    cv_metrics = {
        "accuracy": [],
        "precision": [],
        "recall": [],
        "f1": [],
        "roc_auc": [],
        "brier_score": [],
    }

    for fold, (train_idx, val_idx) in enumerate(sgkf.split(X_train, y_train, groups=groups_train), 1):
        fold_pipeline = create_pipeline()
        fold_pipeline.fit(X_train[train_idx], y_train[train_idx])

        probs = fold_pipeline.predict_proba(X_train[val_idx])[:, 1]
        preds = fold_pipeline.predict(X_train[val_idx])

        acc = float(accuracy_score(y_train[val_idx], preds))
        prec = float(precision_score(y_train[val_idx], preds, zero_division=0))
        rec = float(recall_score(y_train[val_idx], preds, zero_division=0))
        f1 = float(f1_score(y_train[val_idx], preds, zero_division=0))
        auc = float(roc_auc_score(y_train[val_idx], probs))
        brier = float(brier_score_loss(y_train[val_idx], probs))

        cv_metrics["accuracy"].append(acc)
        cv_metrics["precision"].append(prec)
        cv_metrics["recall"].append(rec)
        cv_metrics["f1"].append(f1)
        cv_metrics["roc_auc"].append(auc)
        cv_metrics["brier_score"].append(brier)

        print(f"    Fold {fold}: AUC={auc:.4f} | F1={f1:.4f} | Acc={acc:.4f} | Brier={brier:.4f}")

    cv_summary = {
        metric: {
            "mean": float(np.mean(scores)),
            "std": float(np.std(scores)),
        }
        for metric, scores in cv_metrics.items()
    }

    print(f"\n    --> 5-Fold Group CV Accuracy   : {cv_summary['accuracy']['mean']:.4f} (+/- {cv_summary['accuracy']['std']:.4f})")
    print(f"    --> 5-Fold Group CV Precision  : {cv_summary['precision']['mean']:.4f} (+/- {cv_summary['precision']['std']:.4f})")
    print(f"    --> 5-Fold Group CV Recall     : {cv_summary['recall']['mean']:.4f} (+/- {cv_summary['recall']['std']:.4f})")
    print(f"    --> 5-Fold Group CV F1-Score   : {cv_summary['f1']['mean']:.4f} (+/- {cv_summary['f1']['std']:.4f})")
    print(f"    --> 5-Fold Group CV ROC-AUC    : {cv_summary['roc_auc']['mean']:.4f} (+/- {cv_summary['roc_auc']['std']:.4f})")
    print(f"    --> 5-Fold Group CV Brier Loss : {cv_summary['brier_score']['mean']:.4f} (+/- {cv_summary['brier_score']['std']:.4f})")

    # 2. Fit full training set and evaluate on Holdout
    print("\n[+] Training full model and evaluating on Holdout set...")
    final_pipeline = create_pipeline()
    final_pipeline.fit(X_train, y_train)

    holdout_probs = final_pipeline.predict_proba(X_holdout)[:, 1]
    holdout_preds = final_pipeline.predict(X_holdout)

    holdout_brier = float(brier_score_loss(y_holdout, holdout_probs))
    holdout_results = {
        "accuracy": float(accuracy_score(y_holdout, holdout_preds)),
        "precision": float(precision_score(y_holdout, holdout_preds, zero_division=0)),
        "recall": float(recall_score(y_holdout, holdout_preds, zero_division=0)),
        "f1": float(f1_score(y_holdout, holdout_preds, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_holdout, holdout_probs)),
        "brier_score": holdout_brier,
        "classification_report": classification_report(y_holdout, holdout_preds, output_dict=True, zero_division=0),
    }

    cm = confusion_matrix(y_holdout, holdout_preds).tolist()
    holdout_results["confusion_matrix"] = cm

    print(f"    --> Holdout ROC-AUC  : {holdout_results['roc_auc']:.4f}")
    print(f"    --> Holdout F1-Score : {holdout_results['f1']:.4f}")
    print(f"    --> Holdout Accuracy : {holdout_results['accuracy']:.4f}")
    print(f"    --> Holdout Brier    : {holdout_brier:.4f}")

    # 3. Latency Benchmark
    t0 = time.perf_counter()
    for _ in range(5):
        _ = final_pipeline.predict_proba(X_holdout)
    t1 = time.perf_counter()
    total_samples = len(X_holdout) * 5
    mean_latency_ms = float((t1 - t0) * 1000 / total_samples)

    # 4. 95% Bootstrap Confidence Intervals (B=1000)
    print("\n[+] Computing 95% Bootstrap Confidence Intervals (B=1000)...")
    n_bootstraps = 1000
    rng = np.random.RandomState(42)
    bootstrapped_f1 = []
    bootstrapped_acc = []
    bootstrapped_auc = []
    bootstrapped_brier = []

    for _ in range(n_bootstraps):
        indices = rng.randint(0, len(y_holdout), len(y_holdout))
        if len(np.unique(y_holdout[indices])) < 2:
            continue
        bootstrapped_acc.append(accuracy_score(y_holdout[indices], holdout_preds[indices]))
        bootstrapped_f1.append(f1_score(y_holdout[indices], holdout_preds[indices], zero_division=0))
        bootstrapped_auc.append(roc_auc_score(y_holdout[indices], holdout_probs[indices]))
        bootstrapped_brier.append(brier_score_loss(y_holdout[indices], holdout_probs[indices]))

    ci_95 = {
        "accuracy_ci_95": [float(np.percentile(bootstrapped_acc, 2.5)), float(np.percentile(bootstrapped_acc, 97.5))],
        "f1_ci_95": [float(np.percentile(bootstrapped_f1, 2.5)), float(np.percentile(bootstrapped_f1, 97.5))],
        "roc_auc_ci_95": [float(np.percentile(bootstrapped_auc, 2.5)), float(np.percentile(bootstrapped_auc, 97.5))],
        "brier_ci_95": [float(np.percentile(bootstrapped_brier, 2.5)), float(np.percentile(bootstrapped_brier, 97.5))],
    }
    print(f"    --> Holdout F1 95% CI     : [{ci_95['f1_ci_95'][0]:.4f}, {ci_95['f1_ci_95'][1]:.4f}]")
    print(f"    --> Holdout ROC-AUC 95% CI : [{ci_95['roc_auc_ci_95'][0]:.4f}, {ci_95['roc_auc_ci_95'][1]:.4f}]")
    print(f"    --> Holdout Brier 95% CI   : [{ci_95['brier_ci_95'][0]:.4f}, {ci_95['brier_ci_95'][1]:.4f}]")

    # 4b. Exact McNemar Test (AST Heuristic vs AI Classifier)
    print("\n[+] Computing Exact McNemar Test (AST vs AI on Holdout)...")
    ast_preds = []
    py_ids = {"H-DES-A", "H-XXE-A", "H-XXE-B"}
    for text, item_id in zip(holdout_texts, holdout_ids):
        filename = item_id + (".py" if item_id in py_ids else ".js")
        findings = analyze_source(text, filename)
        ast_preds.append(1 if findings else 0)

    mcnemar_stats = calculate_exact_mcnemar(y_holdout, ast_preds, holdout_preds)
    print(f"    --> McNemar b (AST ok, AI wrong): {mcnemar_stats['b']}")
    print(f"    --> McNemar c (AST wrong, AI ok): {mcnemar_stats['c']}")
    print(f"    --> Exact p-value               : {mcnemar_stats['p_value']:.6f}")
    print(f"    --> Conclusion                  : {mcnemar_stats['interpretation']}")

    # 5. Save model artifact
    model_path = MODELS_DIR / "vuln_classifier.joblib"
    joblib.dump(final_pipeline, model_path)
    print(f"\n[v] Saved production model to: {model_path}")

    # Compute and save SHA-256 checksum
    h = hashlib.sha256()
    with open(model_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    sha256_digest = h.hexdigest()
    checksum_file = MODELS_DIR / "model_checksum.sha256"
    checksum_file.write_text(f"{sha256_digest}  models/vuln_classifier.joblib\n{sha256_digest}  vuln_classifier.joblib\n", encoding="utf-8")
    print(f"[v] Generated model SHA-256 checksum: {sha256_digest}")

    # 6. Save evidence/ai_benchmark.json
    benchmark_data = {
        "metadata": {
            "algorithm": "Pipeline(FeatureUnion[TfidfVectorizer(1-2), SecurityFeatureExtractor] + CalibratedClassifierCV(VotingClassifier[LR, RF], cv=3))",
            "validation_scheme": "StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)",
            "train_samples": len(X_train),
            "holdout_samples": len(X_holdout),
            "train_vulnerable": int(sum(y_train)),
            "holdout_vulnerable": int(sum(y_holdout)),
            "cve_groups_count": int(len(np.unique(groups_train))),
            "sha256_checksum": sha256_digest,
        },
        "latency_benchmark": {
            "mean_latency_ms": round(mean_latency_ms, 3),
            "total_samples_benchmarked": total_samples,
        },
        "bootstrap_ci_95": ci_95,
        "statistical_tests": {
            "mcnemar": mcnemar_stats,
        },
        "cross_validation_5_folds": {
            "folds": cv_metrics,
            "summary": cv_summary,
        },
        "holdout_evaluation": holdout_results,
        "confusion_matrix_holdout": {
            "TN": int(cm[0][0]),
            "FP": int(cm[0][1]),
            "FN": int(cm[1][0]),
            "TP": int(cm[1][1]),
        },
    }

    benchmark_path = EVIDENCE_DIR / "ai_benchmark.json"
    with open(benchmark_path, "w", encoding="utf-8") as f:
        json.dump(benchmark_data, f, indent=2, ensure_ascii=False)
    print(f"[v] Saved benchmark results to: {benchmark_path}")

    # 7. Plot confusion matrix
    cm_plot_path = EVIDENCE_DIR / "confusion_matrix.png"
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from sklearn.metrics import ConfusionMatrixDisplay

        fig, ax = plt.subplots(figsize=(6, 5))
        disp = ConfusionMatrixDisplay(
            confusion_matrix=np.array(cm),
            display_labels=["Safe (0)", "Vulnerable (1)"],
        )
        disp.plot(cmap="Blues", values_format="d", ax=ax, colorbar=False)
        ax.set_title("Holdout Confusion Matrix (Calibrated Voting Classifier)")
        plt.tight_layout()
        plt.savefig(cm_plot_path, dpi=300)
        plt.close()
        print(f"[v] Saved confusion matrix plot to: {cm_plot_path}")
    except Exception as ex:
        print(f"[!] Could not plot with matplotlib: {ex}")

    # 8. Print Markdown summary
    print("\n" + "=" * 70)
    print("      AI MODEL BENCHMARK SUMMARY TABLE")
    print("=" * 70)
    table_md = f"""
| Metric            | 5-Fold Group CV (Mean +/- Std)        | Holdout Set (N={len(y_holdout)}) |
| :---------------- | :-----------------------------------: | :-----------------------: |
| **Accuracy**      | {cv_summary['accuracy']['mean']:.4f} +/- {cv_summary['accuracy']['std']:.4f}          | {holdout_results['accuracy']:.4f}                    |
| **Precision**     | {cv_summary['precision']['mean']:.4f} +/- {cv_summary['precision']['std']:.4f}          | {holdout_results['precision']:.4f}                    |
| **Recall**        | {cv_summary['recall']['mean']:.4f} +/- {cv_summary['recall']['std']:.4f}          | {holdout_results['recall']:.4f}                    |
| **F1-Score**      | {cv_summary['f1']['mean']:.4f} +/- {cv_summary['f1']['std']:.4f}          | {holdout_results['f1']:.4f}                    |
| **ROC-AUC**       | {cv_summary['roc_auc']['mean']:.4f} +/- {cv_summary['roc_auc']['std']:.4f}          | {holdout_results['roc_auc']:.4f}                    |
| **Brier Loss**    | {cv_summary['brier_score']['mean']:.4f} +/- {cv_summary['brier_score']['std']:.4f}          | {holdout_brier:.4f}                    |

### Holdout Confusion Matrix:
- True Negative  (Safe -> Predicted Safe)        : {cm[0][0]}
- False Positive (Safe -> Predicted Vulnerable)  : {cm[0][1]}
- False Negative (Vulnerable -> Predicted Safe)  : {cm[1][0]}
- True Positive  (Vulnerable -> Pred Vulnerable) : {cm[1][1]}
"""
    print(table_md)
    print("=" * 70)


if __name__ == "__main__":
    main()
