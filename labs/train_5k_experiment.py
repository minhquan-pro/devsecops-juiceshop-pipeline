#!/usr/bin/env python3
"""
labs/train_5k_experiment.py
--------------------------------------------------------------------------------
Thực nghiệm huấn luyện & so sánh thực tế trên 5.000 mẫu (data/augmented_5000.json):
- Model A: Calibrated Soft-Voting Ensemble (Logistic Regression + Random Forest + Sigmoid Calibration)
- Model B: Deep Learning / Neural Network (MLPClassifier với early stopping)

Áp dụng StratifiedGroupKFold(n_splits=5) theo group_id nhằm triệt tiêu hoàn toàn
nguy cơ rò rỉ dữ liệu giữa các biến thể đối ngẫu (Contrastive Pair Leakage).
Đo đạc: ROC-AUC, F1-Score, Brier Score, Accuracy, Precision, Recall, Train Time, Inference Latency.
Xuất kết quả chi tiết ra: evidence/synthetic_5k_benchmark.json
--------------------------------------------------------------------------------
"""

import os
import sys
import json
import time
import logging
from pathlib import Path
from typing import Dict, Any, List, Tuple

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

import numpy as np
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    roc_auc_score,
    f1_score,
    brier_score_loss,
    accuracy_score,
    precision_score,
    recall_score
)

# Thiết lập đường dẫn import module juicesec
CURRENT_DIR = Path(__file__).resolve().parent
ROOT_DIR = CURRENT_DIR.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Cấu hình logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("Train5kExperiment")

# Import SecurityFeatureExtractor chuẩn từ juicesec.ai_classifier
from juicesec.ai_classifier import SecurityFeatureExtractor


def load_dataset(data_path: Path) -> Tuple[List[str], np.ndarray, np.ndarray]:
    """
    Nạp dữ liệu từ data/augmented_5000.json, trích xuất code, label, group_id.
    """
    if not data_path.exists():
        raise FileNotFoundError(f"Không tìm thấy file dữ liệu tại: {data_path}")

    logger.info(f"Đang nạp tập dữ liệu từ: {data_path.resolve()}")
    with open(data_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError("Dữ liệu JSON phải là mảng các đối tượng (list of dicts).")

    payloads = []
    labels = []
    groups = []

    for idx, item in enumerate(data):
        code = item.get("code") or item.get("payload") or item.get("input") or ""
        label = item.get("label", 0)
        group_id = item.get("group_id", f"GROUP-{idx}")

        payloads.append(str(code))
        labels.append(int(label))
        groups.append(str(group_id))

    labels_arr = np.array(labels, dtype=np.int32)
    groups_arr = np.array(groups)

    n_vuln = int(np.sum(labels_arr == 1))
    n_benign = int(np.sum(labels_arr == 0))
    n_groups = len(set(groups))
    logger.info(f"Nạp thành công {len(payloads)} mẫu ({n_vuln} Vuln, {n_benign} Benign).")
    logger.info(f"Số lượng nhóm độc lập (Unique Groups): {n_groups} nhóm đối ngẫu.")

    return payloads, labels_arr, groups_arr


def build_model_a() -> CalibratedClassifierCV:
    """
    Khởi tạo Model A: Calibrated Soft-Voting Ensemble (Kiến trúc chuẩn production).
    """
    clf_lr = LogisticRegression(
        C=1.0,
        max_iter=1000,
        solver="lbfgs",
        random_state=42
    )
    clf_rf = RandomForestClassifier(
        max_depth=16,
        n_estimators=100,
        random_state=42,
        n_jobs=-1
    )
    ensemble = VotingClassifier(
        estimators=[("lr", clf_lr), ("rf", clf_rf)],
        voting="soft"
    )
    try:
        calibrated = CalibratedClassifierCV(estimator=ensemble, method="sigmoid", cv=3)
    except TypeError:
        calibrated = CalibratedClassifierCV(base_estimator=ensemble, method="sigmoid", cv=3)

    return calibrated


def build_model_b() -> Pipeline:
    """
    Khởi tạo Model B: Mạng Nơ-ron (MLPClassifier) kết hợp StandardScaler (with_mean=False cho sparse).
    Hidden layers: (64, 32), Activation: ReLU, Solver: Adam, Early Stopping: True.
    """
    scaler = StandardScaler(with_mean=False)
    mlp = MLPClassifier(
        hidden_layer_sizes=(64, 32),
        activation="relu",
        solver="adam",
        alpha=0.001,
        early_stopping=True,
        n_iter_no_change=10,
        max_iter=200,
        random_state=42
    )
    return Pipeline([("scaler", scaler), ("mlp", mlp)])


def evaluate_metrics(y_true: np.ndarray, y_pred_proba: np.ndarray, threshold: float = 0.5) -> Dict[str, float]:
    """Tính toán 6 chỉ số đánh giá kỹ thuật chuyên sâu."""
    y_pred = (y_pred_proba >= threshold).astype(int)
    return {
        "roc_auc": float(roc_auc_score(y_true, y_pred_proba)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "brier": float(brier_score_loss(y_true, y_pred_proba)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0))
    }


def benchmark_fold(
    model,
    X_train,
    y_train: np.ndarray,
    X_test,
    y_test: np.ndarray
) -> Tuple[Dict[str, float], float, float]:
    """
    Huấn luyện và đo đạc một fold:
    - Thời gian huấn luyện (seconds)
    - Độ trễ suy luận chuẩn hoá (ms/1000 samples)
    """
    start_train = time.perf_counter()
    model.fit(X_train, y_train)
    train_time_sec = time.perf_counter() - start_train

    start_infer = time.perf_counter()
    y_pred_proba = model.predict_proba(X_test)[:, 1]
    infer_time_sec = time.perf_counter() - start_infer

    n_samples = X_test.shape[0] if hasattr(X_test, "shape") else len(X_test)
    latency_ms_per_1k = (infer_time_sec / max(n_samples, 1)) * 1_000_000.0

    metrics = evaluate_metrics(y_test, y_pred_proba)
    return metrics, train_time_sec, latency_ms_per_1k


def print_comparison_table(results_a: Dict[str, Any], results_b: Dict[str, Any]):
    """Hiển thị bảng đối sánh thực nghiệm trên Terminal."""
    headers = ["Chỉ Số Kỹ Thuật", "Model A (Calibrated Ensemble)", "Model B (Neural Network MLP)", "Chênh Lệch (A - B)"]
    row_fmt = "| {:<22} | {:<28} | {:<28} | {:<18} |"
    sep = "+" + "-" * 24 + "+" + "-" * 30 + "+" + "-" * 30 + "+" + "-" * 20 + "+"

    print("\n" + "=" * 110)
    print("        BẢNG ĐỐI SÁNH THỰC NGHIỆM 5-FOLD STRATIFIED GROUP CV TRÊN 5.000 MẪU ĐỐI NGẪU")
    print("=" * 110)
    print(sep)
    print(f"| {headers[0]:<22} | {headers[1]:<28} | {headers[2]:<28} | {headers[3]:<18} |")
    print(sep)

    metric_keys = [
        ("ROC-AUC (CV)", "roc_auc"),
        ("F1-Score (CV)", "f1"),
        ("Brier Score Loss", "brier"),
        ("Accuracy", "accuracy"),
        ("Precision", "precision"),
        ("Recall", "recall"),
        ("Train Time (giây)", "train_time_sec"),
        ("Inference (ms/1k mẫu)", "latency_ms_per_1k"),
    ]

    for label, key in metric_keys:
        val_a = results_a["summary"][key]["mean"]
        std_a = results_a["summary"][key]["std"]
        val_b = results_b["summary"][key]["mean"]
        std_b = results_b["summary"][key]["std"]
        diff = val_a - val_b

        str_a = f"{val_a:.4f} ± {std_a:.4f}"
        str_b = f"{val_b:.4f} ± {std_b:.4f}"
        str_diff = f"{diff:+.4f}"

        print(row_fmt.format(label, str_a, str_b, str_diff))

    print(sep + "\n")


def main():
    data_file = ROOT_DIR / "data" / "augmented_5000.json"
    evidence_dir = ROOT_DIR / "evidence"
    output_file = evidence_dir / "synthetic_5k_benchmark.json"

    evidence_dir.mkdir(parents=True, exist_ok=True)

    # 1. Nạp tập dữ liệu 5.000 mẫu
    payloads, labels, groups = load_dataset(data_file)

    # 2. Thiết lập StratifiedGroupKFold 5-Folds
    sgkf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)

    fold_results_a: List[Dict[str, float]] = []
    fold_results_b: List[Dict[str, float]] = []

    print("\n" + "=" * 70)
    print(" BẮT ĐẦU HUẤN LUYỆN ĐỐI SÁNH 5 FOLDS (STRATIFIED GROUP CV)")
    print("=" * 70)

    for fold_idx, (train_idx, test_idx) in enumerate(sgkf.split(payloads, labels, groups), 1):
        print(f"\n--- [FOLD {fold_idx}/5] (Train: {len(train_idx)} mẫu, Test: {len(test_idx)} mẫu) ---")
        
        train_texts = [payloads[i] for i in train_idx]
        test_texts = [payloads[i] for i in test_idx]
        y_train, y_test = labels[train_idx], labels[test_idx]

        # Trích xuất đặc trưng độc lập trên từng fold chống data leakage
        extractor = SecurityFeatureExtractor()
        X_train = extractor.fit_transform(train_texts)
        X_test = extractor.transform(test_texts)

        # Huấn luyện & Đánh giá Model A (Calibrated Ensemble)
        model_a = build_model_a()
        metrics_a, t_train_a, lat_a = benchmark_fold(model_a, X_train, y_train, X_test, y_test)
        metrics_a["train_time_sec"] = t_train_a
        metrics_a["latency_ms_per_1k"] = lat_a
        metrics_a["fold"] = fold_idx
        fold_results_a.append(metrics_a)

        # Huấn luyện & Đánh giá Model B (MLP Classifier)
        model_b = build_model_b()
        metrics_b, t_train_b, lat_b = benchmark_fold(model_b, X_train, y_train, X_test, y_test)
        metrics_b["train_time_sec"] = t_train_b
        metrics_b["latency_ms_per_1k"] = lat_b
        metrics_b["fold"] = fold_idx
        fold_results_b.append(metrics_b)

        print(f" > Model A (Ensemble): ROC-AUC = {metrics_a['roc_auc']:.4f} | F1 = {metrics_a['f1']:.4f} | Brier = {metrics_a['brier']:.4f} | Train = {t_train_a:.2f}s")
        print(f" > Model B (MLP Net):  ROC-AUC = {metrics_b['roc_auc']:.4f} | F1 = {metrics_b['f1']:.4f} | Brier = {metrics_b['brier']:.4f} | Train = {t_train_b:.2f}s")

    # 3. Tổng hợp số liệu Mean & Standard Deviation
    def aggregate_metrics(fold_list: List[Dict[str, float]]) -> Dict[str, Dict[str, float]]:
        summary = {}
        keys = ["roc_auc", "f1", "brier", "accuracy", "precision", "recall", "train_time_sec", "latency_ms_per_1k"]
        for k in keys:
            vals = [f[k] for f in fold_list]
            summary[k] = {
                "mean": float(np.mean(vals)),
                "std": float(np.std(vals)),
                "min": float(np.min(vals)),
                "max": float(np.max(vals))
            }
        return summary

    summary_a = aggregate_metrics(fold_results_a)
    summary_b = aggregate_metrics(fold_results_b)

    final_payload_a = {
        "model_name": "Calibrated Soft-Voting Ensemble (LogisticRegression + RandomForest)",
        "summary": summary_a,
        "folds": fold_results_a
    }
    final_payload_b = {
        "model_name": "Deep Learning / Neural Network (MLPClassifier 64x32 ReLU)",
        "summary": summary_b,
        "folds": fold_results_b
    }

    # 4. In bảng so sánh đối đầu
    print_comparison_table(final_payload_a, final_payload_b)

    # 5. Xuất báo cáo chứng cứ JSON
    experiment_report = {
        "metadata": {
            "dataset": str(data_file.relative_to(ROOT_DIR)),
            "total_samples": len(payloads),
            "n_splits": 5,
            "validation_strategy": "StratifiedGroupKFold",
            "feature_extractor": "SecurityFeatureExtractor (53 domain security features)",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
        "model_a_calibrated_ensemble": final_payload_a,
        "model_b_neural_network_mlp": final_payload_b
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(experiment_report, f, indent=2, ensure_ascii=False)

    print(f"[✓] Đã xuất chứng cứ thực nghiệm đầy đủ ra: {output_file.resolve()}")


if __name__ == "__main__":
    main()
