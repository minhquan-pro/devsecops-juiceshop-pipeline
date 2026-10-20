"""
juicesec/ai_classifier.py
Module suy luận AI/Heuristic đánh giá rủi ro mã nguồn và điều chỉnh điểm số phát hiện của AST.
Hỗ trợ nạp model Machine Learning (scikit-learn/joblib) hoặc fallback Heuristic an toàn (Zero-Crash).
Tích hợp:
- Bounded input (4096 bytes) chống DoS và Context Dilution.
- Asymmetric Security Thresholds: Bảo vệ nghiêm ngặt các phát hiện HIGH/CRITICAL, ngăn chặn False Negatives.
- SecurityFeatureExtractor tương thích Scikit-Learn Pipeline và an toàn khi deserialize Joblib.
- SHA-256 Checksum Verification chống Deserialization RCE.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

import numpy as np
from scipy.sparse import csr_matrix
from sklearn.base import BaseEstimator, TransformerMixin

try:
    import joblib
    HAS_JOBLIB = True
except ImportError:
    HAS_JOBLIB = False

# Giới hạn kích thước đầu vào chống DoS và context dilution (4096 chars / bytes)
MAX_CODE_INPUT_LIMIT: int = 4096


def bound_input_code(code: Any) -> str:
    """Cắt ngắn dữ liệu code tối đa 4096 ký tự / bytes để chống DoS và Context Dilution."""
    if code is None:
        return ""
    if not isinstance(code, str):
        code = str(code)
    truncated = code[:MAX_CODE_INPUT_LIMIT]
    raw_bytes = truncated.encode("utf-8", errors="ignore")[:MAX_CODE_INPUT_LIMIT]
    return raw_bytes.decode("utf-8", errors="ignore")


class SecurityFeatureExtractor(BaseEstimator, TransformerMixin):
    """
    Trích xuất đặc trưng domain AST và Code Security từ mã nguồn.
    Hoàn toàn tương thích Scikit-Learn Pipeline và an toàn khi serialize/deserialize với Joblib.
    """

    def __init__(self, include_code_stats: bool = True):
        self.include_code_stats = include_code_stats

    def fit(self, X: Sequence[str] | Any, y: Any = None) -> "SecurityFeatureExtractor":
        return self

    def transform(self, X: Sequence[str] | Any) -> csr_matrix:
        if hasattr(X, "tolist"):
            X = X.tolist()
        elif not isinstance(X, (list, tuple)):
            X = list(X)

        features = []
        for raw_code in X:
            text = bound_input_code(raw_code)
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

            row = [
                has_sql_kw, has_sql_sink, has_dom_sink, has_eval_sink, has_file_sink, has_proto_sink, has_tmpl_sink, has_nosql_sink, has_crypto_sink,
                has_yaml_sink, has_xml_sink, has_ssrf_sink, has_csrf_risk,
                has_source, has_concat, sql_concat, dom_concat, file_concat, eval_source, ssrf_source,
                has_param, has_safe_dom, has_path_safe, has_safe_yaml, has_safe_xml, has_safe_eval, has_validate, is_pure_comment,
                is_definitely_vuln, is_definitely_safe
            ]

            if self.include_code_stats:
                row.extend([float(len(text)), float(text.count("\n") + 1)])

            features.append(row)

        return csr_matrix(features, dtype=np.float64)

    def get_feature_names_out(self, input_features: Any = None) -> np.ndarray:
        names = [
            "has_sql_kw", "has_sql_sink", "has_dom_sink", "has_eval_sink", "has_file_sink", "has_proto_sink", "has_tmpl_sink", "has_nosql_sink", "has_crypto_sink",
            "has_yaml_sink", "has_xml_sink", "has_ssrf_sink", "has_csrf_risk",
            "has_source", "has_concat", "sql_concat", "dom_concat", "file_concat", "eval_source", "ssrf_source",
            "has_param", "has_safe_dom", "has_path_safe", "has_safe_yaml", "has_safe_xml", "has_safe_eval", "has_validate", "is_pure_comment",
            "is_definitely_vuln", "is_definitely_safe"
        ]
        if self.include_code_stats:
            names.extend(["char_count", "line_count"])
        return np.array(names, dtype=object)


# 30 AST Security Domain Features Metadata
FEATURE_METADATA = [
    # Sinks (0..12)
    {"id": "has_sql_kw", "name": "SQL Keywords", "category": "sink", "desc": "Từ khóa SQL nguy cơ cao: SELECT, INSERT, UPDATE, DELETE, UNION..."},
    {"id": "has_sql_sink", "name": "SQL Query Sink", "category": "sink", "desc": "Hàm thực thi truy vấn trực tiếp: db.query, db.execute..."},
    {"id": "has_dom_sink", "name": "DOM XSS Sink", "category": "sink", "desc": "DOM write/modification: innerHTML, outerHTML, document.write"},
    {"id": "has_eval_sink", "name": "Code Injection Sink", "category": "sink", "desc": "Dynamic execution: eval, Function, child_process.exec, execSync"},
    {"id": "has_file_sink", "name": "File I/O Sink", "category": "sink", "desc": "Thao tác filesystem: writeFile, readFile, createReadStream, open"},
    {"id": "has_proto_sink", "name": "Prototype Pollution Sink", "category": "sink", "desc": "Biến đổi đối tượng: merge, cloneDeep, __proto__, constructor.prototype"},
    {"id": "has_tmpl_sink", "name": "Template Injection Sink", "category": "sink", "desc": "Template compilation/rendering: template, compile, render"},
    {"id": "has_nosql_sink", "name": "NoSQL Injection Sink", "category": "sink", "desc": "NoSQL raw query operators: $where, $regex, $gt, $ne"},
    {"id": "has_crypto_sink", "name": "Weak Crypto Sink", "category": "sink", "desc": "Thuật toán băm/mã hóa yếu: MD5, SHA1, DES, createCipher"},
    {"id": "has_yaml_sink", "name": "Unsafe YAML Sink", "category": "sink", "desc": "YAML deserialization không an toàn: yaml.load (thiếu safe_load)"},
    {"id": "has_xml_sink", "name": "XXE XML Sink", "category": "sink", "desc": "XML parser dễ bị XXE: parseString, etree (không dùng defusedxml)"},
    {"id": "has_ssrf_sink", "name": "SSRF Network Sink", "category": "sink", "desc": "HTTP request ra ngoài: urllib.request, requests.get, fetch"},
    {"id": "has_csrf_risk", "name": "State-changing GET Risk", "category": "sink", "desc": "HTTP GET route thực hiện đổi trạng thái/xóa dữ liệu"},

    # Sources & Flows (13..19)
    {"id": "has_source", "name": "User Input Source", "category": "source", "desc": "Nguồn dữ liệu người dùng: req.body, req.query, params, location.hash"},
    {"id": "has_concat", "name": "String Concat in Payload", "category": "flow", "desc": "Nối chuỗi trực tiếp (+ hoặc template literal) với user input"},
    {"id": "sql_concat", "name": "Tainted SQL Flow", "category": "flow", "desc": "Dòng dữ liệu tainted từ source chảy trực tiếp vào SQL sink"},
    {"id": "dom_concat", "name": "Tainted DOM Flow", "category": "flow", "desc": "Dòng dữ liệu tainted từ source chảy vào innerHTML / DOM"},
    {"id": "file_concat", "name": "Tainted Filepath Flow", "category": "flow", "desc": "User input chảy trực tiếp vào đường dẫn file I/O (Path Traversal)"},
    {"id": "eval_source", "name": "Tainted Eval Flow", "category": "flow", "desc": "User input được truyền trực tiếp vào hàm eval / code execution"},
    {"id": "ssrf_source", "name": "Tainted SSRF Flow", "category": "flow", "desc": "User input cấu thành URL gọi mạng bên ngoài (SSRF)"},

    # Sanitizers & Defenses (20..27)
    {"id": "has_param", "name": "Parameterized Query", "category": "sanitizer", "desc": "Truy vấn an toàn có tham số hóa (?, $1, :param, binding array)"},
    {"id": "has_safe_dom", "name": "Safe DOM Setter", "category": "sanitizer", "desc": "Gán text an toàn chống XSS: textContent, innerText"},
    {"id": "has_path_safe", "name": "Path Canonicalization", "category": "sanitizer", "desc": "Khử Path Traversal: path.basename, path.resolve an toàn"},
    {"id": "has_safe_yaml", "name": "Safe YAML Loader", "category": "sanitizer", "desc": "Sử dụng yaml.safe_load hoặc SafeLoader an toàn"},
    {"id": "has_safe_xml", "name": "Defused XML Parser", "category": "sanitizer", "desc": "Sử dụng defusedxml hoặc vô hiệu hóa DTD/entity expansion"},
    {"id": "has_safe_eval", "name": "Safe AST Literal Eval", "category": "sanitizer", "desc": "Sử dụng ast.literal_eval thay vì eval toàn năng"},
    {"id": "has_validate", "name": "Input Validator / Sanitizer", "category": "sanitizer", "desc": "Kiểm tra whitelist / sanitize: DOMPurify, validator, escape"},
    {"id": "is_pure_comment", "name": "Comment / Inactive Code", "category": "sanitizer", "desc": "Đoạn mã chỉ chứa chú thích hoặc không có logic khả thi"},

    # High-level Indicators (28..29)
    {"id": "is_definitely_vuln", "name": "Definite Exploit Vector", "category": "indicator", "desc": "Chỉ báo nguy cơ cao: Luồng dữ liệu độc hại không qua bộ lọc"},
    {"id": "is_definitely_safe", "name": "Definite Guard Vector", "category": "indicator", "desc": "Chỉ báo phòng thủ vững chắc: Áp dụng cơ chế an toàn tương ứng"}
]


class VulnerabilityAIClassifier:
    """Bộ phân loại rủi ro bảo mật mã nguồn bằng Model Joblib hoặc Fallback Heuristic."""

    DEFAULT_MODEL_REL_PATH = Path("models") / "vuln_classifier.joblib"
    DEFAULT_CHECKSUM_REL_PATH = Path("models") / "model_checksum.sha256"

    # Tập pattern heuristic fallback khi không có model ML
    HEURISTIC_PATTERNS = [
        (re.compile(r"\b(eval|exec)\s*\("), 0.85, "Code execution sink detected"),
        (re.compile(r"\b(os\.system|subprocess\.Popen|subprocess\.call|subprocess\.run)\s*\("), 0.80, "Command execution sink detected"),
        (re.compile(r"\bpickle\.(loads|load)\s*\("), 0.85, "Unsafe deserialization sink detected"),
        (re.compile(r"\byaml\.(load|unsafe_load)\s*\("), 0.75, "Potentially unsafe YAML load detected"),
        (re.compile(r"(cursor|db)\.(execute|query)\s*\(\s*f?[\"'].*?(\+|%|\$)"), 0.85, "Potential SQL concatenation detected"),
        (re.compile(r"(?i)(password|secret|api_key|access_token)\s*=\s*['\"][A-Za-z0-9_\-\.\/+=]{8,}['\"]"), 0.70, "Hardcoded credential detected"),
    ]

    def __init__(self, model_path: Optional[str] = None) -> None:
        self.model = None
        self.mode = "heuristic"
        self.model_name = "heuristic_fallback"

        resolved_path = self._resolve_model_path(model_path)

        if HAS_JOBLIB and resolved_path and resolved_path.is_file():
            if not self.verify_model_integrity(resolved_path):
                self.model = None
                self.mode = "heuristic"
                self.model_name = "heuristic_fallback_integrity_mismatch"
            else:
                try:
                    self.model = joblib.load(resolved_path)
                    self.mode = "ml"
                    self.model_name = resolved_path.name
                except Exception:
                    self.model = None
                    self.mode = "heuristic"
                    self.model_name = "heuristic_fallback"

    @classmethod
    def verify_model_integrity(cls, model_path: Path) -> bool:
        """
        Xác thực tính toàn vẹn của model joblib bằng mã băm SHA-256 để phòng chống Pickle Deserialization RCE.
        Nếu có tệp checksum (.sha256), mã băm thực tế của model phải khớp 100%.
        Nếu không có tệp checksum, cho phép nạp nhưng cảnh báo.
        """
        checksum_path = model_path.with_suffix(".sha256")
        if not checksum_path.is_file():
            cwd_chk = Path.cwd() / cls.DEFAULT_CHECKSUM_REL_PATH
            if cwd_chk.is_file():
                checksum_path = cwd_chk
            else:
                pkg_chk = Path(__file__).resolve().parent.parent / cls.DEFAULT_CHECKSUM_REL_PATH
                if pkg_chk.is_file():
                    checksum_path = pkg_chk

        if not checksum_path.is_file():
            return True

        try:
            expected_content = checksum_path.read_text(encoding="utf-8").strip()
            expected_hash = expected_content.split()[0].lower()
            h = hashlib.sha256()
            with open(model_path, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            actual_hash = h.hexdigest().lower()
            return actual_hash == expected_hash
        except Exception:
            return False

    def _resolve_model_path(self, model_path: Optional[str]) -> Optional[Path]:
        """Xác định đường dẫn model từ tham số hoặc vị trí mặc định dự án."""
        if model_path:
            p = Path(model_path)
            return p if p.exists() else None

        cwd_target = Path.cwd() / self.DEFAULT_MODEL_REL_PATH
        if cwd_target.is_file():
            return cwd_target

        pkg_target = Path(__file__).resolve().parent.parent / self.DEFAULT_MODEL_REL_PATH
        if pkg_target.is_file():
            return pkg_target

        return None

    def _heuristic_predict(self, source_code: str) -> Dict[str, Any]:
        """Fallback tính toán xác suất dựa trên luật tĩnh khi không có ML."""
        clean_code = bound_input_code(source_code)
        max_score = 0.05
        matched_details = []

        for pattern, weight, label in self.HEURISTIC_PATTERNS:
            if pattern.search(clean_code):
                matched_details.append(label)
                if weight > max_score:
                    max_score = weight

        if len(matched_details) > 1:
            max_score = min(0.95, max_score + 0.05 * (len(matched_details) - 1))

        is_vulnerable = max_score >= 0.50
        details = "; ".join(matched_details) if matched_details else "No suspicious patterns identified"

        return {
            "is_vulnerable": is_vulnerable,
            "confidence": round(max_score, 4),
            "model": "heuristic_fallback",
            "details": details,
        }

    def predict_code(self, source_code: str) -> Dict[str, Any]:
        """Dự đoán mã nguồn có lỗ hổng hay không và trả về độ tin cậy."""
        if not isinstance(source_code, str) or not source_code.strip():
            return {
                "is_vulnerable": False,
                "confidence": 0.0,
                "model": self.model_name,
                "details": "Empty or invalid source code",
            }

        bounded_code = bound_input_code(source_code)

        if self.mode == "ml" and self.model is not None:
            try:
                if hasattr(self.model, "predict_proba"):
                    probs = self.model.predict_proba([bounded_code])[0]
                    confidence = float(probs[1]) if len(probs) > 1 else float(probs[0])
                elif hasattr(self.model, "decision_function"):
                    score = float(self.model.decision_function([bounded_code])[0])
                    confidence = 1.0 / (1.0 + math.exp(-score))
                else:
                    pred = self.model.predict([bounded_code])[0]
                    confidence = 0.90 if pred in [1, True, "1", "VULNERABLE"] else 0.10

                return {
                    "is_vulnerable": confidence >= 0.50,
                    "confidence": round(confidence, 4),
                    "model": self.model_name,
                    "details": f"ML model inference completed (confidence: {confidence:.2f})",
                }
            except Exception as ex:
                heuristic_res = self._heuristic_predict(bounded_code)
                heuristic_res["details"] += f" (Fallback: {str(ex)})"
                return heuristic_res

        return self._heuristic_predict(bounded_code)

    def get_detailed_explanation(self, source_code: str) -> Dict[str, Any]:
        """
        Trích xuất giải thích chi tiết Explainable AI (XAI):
        - Dự đoán xác suất bằng ML hoặc Heuristic.
        - Trích xuất các đặc trưng AST (Active Features) kích hoạt trong mã nguồn.
        - Phân nhóm đặc trưng (Sources, Sinks, Sanitizers, Data-flow, Indicators).
        - Trả về cấu trúc JSON trực quan hóa cho UI Dashboard & Audit.
        """
        code = bound_input_code(source_code)
        prediction = self.predict_code(code)
        extractor = SecurityFeatureExtractor(include_code_stats=False)
        matrix = extractor.transform([code])
        names = extractor.get_feature_names_out()
        values = matrix.toarray()[0]

        feature_map = {meta["id"]: meta for meta in FEATURE_METADATA}

        active_features = []
        categories_breakdown = {"source": 0, "sink": 0, "sanitizer": 0, "flow": 0, "indicator": 0}

        for name, val in zip(names, values):
            if val > 0:
                meta = feature_map.get(name, {"id": name, "name": name, "category": "unknown", "desc": ""})
                cat = meta.get("category", "unknown")
                if cat in categories_breakdown:
                    categories_breakdown[cat] += 1
                active_features.append({
                    "id": name,
                    "name": meta.get("name", name),
                    "category": cat,
                    "desc": meta.get("desc", ""),
                    "value": float(val)
                })

        conf = prediction.get("confidence", 0.0)
        if conf >= 0.85:
            risk_level = "CRITICAL"
        elif conf >= 0.70:
            risk_level = "HIGH"
        elif conf >= 0.50:
            risk_level = "MEDIUM"
        elif conf >= 0.20:
            risk_level = "LOW"
        else:
            risk_level = "CLEAN"

        return {
            "prediction": prediction,
            "risk_level": risk_level,
            "confidence": conf,
            "model_mode": self.mode,
            "model_name": self.model_name,
            "active_features": active_features,
            "categories_breakdown": categories_breakdown,
            "total_active_features": len(active_features),
            "code_bounded_length": len(code)
        }

    def predict_batch(self, code_snippets: List[str]) -> List[Dict[str, Any]]:
        """
        Dự đoán hàng loạt đoạn mã theo lô (Batch Vectorization & Inference).
        Tối ưu hóa P99 latency bằng cách thực thi ma trận hóa 1 lần duy nhất trên CPU.
        """
        if not code_snippets:
            return []

        clean_snippets = [bound_input_code(c) for c in code_snippets]

        if self.mode == "ml" and self.model is not None:
            try:
                if hasattr(self.model, "predict_proba"):
                    probs_matrix = self.model.predict_proba(clean_snippets)
                    results = []
                    for probs in probs_matrix:
                        confidence = float(probs[1]) if len(probs) > 1 else float(probs[0])
                        results.append({
                            "is_vulnerable": confidence >= 0.50,
                            "confidence": round(confidence, 4),
                            "model": self.model_name,
                            "details": f"Batch ML inference completed (confidence: {confidence:.2f})",
                        })
                    return results
            except Exception:
                pass  # Fallback to per-snippet evaluation if batch fails

        return [self.predict_code(code) for code in clean_snippets]

    def rescore_ast_findings(self, findings: List[Dict[str, Any]], source_code: str = "") -> List[Dict[str, Any]]:
        """
        Nhận danh sách findings từ AST Scan, tính toán lại độ ưu tiên và
        bổ sung trường ai_confidence, ai_model, và điều chỉnh severity.
        
        Triển khai Asymmetric Security Risk Policy (rfc 2119):
        - Tuyệt đối KHÔNG hạ cấp phát hiện AST có mức CRITICAL hoặc HIGH xuống MEDIUM/LOW dù AI score thấp
          (ngăn chặn triệt để thảm hoạ False Negatives trong DevSecOps).
        - Chỉ cho phép nâng cấp severity hoặc tăng confidence khi AI phát hiện mẫu nguy hiểm cao.
        - Phát hiện LOW/INFO có thể được nâng lên MEDIUM nếu AI phát hiện xác suất cao (>= 0.85).
        - Gắn cờ potential_false_positive phục vụ audit log mà không đánh tụt mức độ nghiêm trọng gốc của AST.
        """
        if not findings:
            return []

        global_ai = self.predict_code(source_code) if source_code else {"confidence": 0.5, "model": self.model_name}
        rescored = []

        severity_levels = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

        # Tối ưu hóa: Thu thập toàn bộ snippets để chạy Batch Inference
        snippets_to_predict = []
        snippet_indices = []
        for idx, item in enumerate(findings):
            finding = dict(item) if isinstance(item, dict) else item.__dict__.copy()
            snippet = finding.get("snippet") or finding.get("line_content") or finding.get("code")
            if snippet and isinstance(snippet, str) and snippet.strip():
                snippets_to_predict.append(snippet)
                snippet_indices.append(idx)

        # Thực thi Batch Inference cho toàn bộ snippets
        batch_confidences = {}
        if snippets_to_predict:
            batch_results = self.predict_batch(snippets_to_predict)
            for s_idx, b_res in zip(snippet_indices, batch_results):
                batch_confidences[s_idx] = b_res["confidence"]

        for idx, item in enumerate(findings):
            finding = dict(item) if isinstance(item, dict) else item.__dict__.copy()

            if idx in batch_confidences:
                snippet_conf = batch_confidences[idx]
                combined_confidence = self._probabilistic_fusion(
                    snippet_conf, global_ai["confidence"], w_local=0.7, w_global=0.3
                )
            else:
                snippet = finding.get("snippet") or finding.get("line_content") or finding.get("code")
                if snippet and isinstance(snippet, str) and snippet.strip():
                    local_ai = self.predict_code(snippet)
                    combined_confidence = self._probabilistic_fusion(
                        local_ai["confidence"], global_ai["confidence"], w_local=0.7, w_global=0.3
                    )
                else:
                    combined_confidence = global_ai["confidence"]

            original_sev = str(finding.get("severity", "MEDIUM")).upper()
            adjusted_sev = original_sev

            # Asymmetric Risk Decision Logic:
            if combined_confidence >= 0.85:
                if original_sev in ["LOW", "INFO"]:
                    adjusted_sev = "MEDIUM"
                elif original_sev == "MEDIUM":
                    adjusted_sev = "HIGH"
            elif combined_confidence <= 0.20:
                # ASYMMETRIC SECURITY GUARD: Never downgrade CRITICAL or HIGH to MEDIUM/LOW
                if original_sev in ["HIGH", "CRITICAL"]:
                    # Do NOT downgrade severity to MEDIUM; flag for human review
                    adjusted_sev = original_sev
                    finding["potential_false_positive"] = True
                    finding["ai_audit_note"] = "Low AI confidence but AST Critical/High severity retained by Asymmetric Risk Policy"
                elif original_sev == "MEDIUM":
                    adjusted_sev = "LOW"
                    finding["potential_false_positive"] = True

            finding["ai_confidence"] = combined_confidence
            finding["ai_model"] = global_ai["model"]
            finding["ai_rescored"] = True
            finding["original_severity"] = original_sev
            finding["severity"] = adjusted_sev if adjusted_sev in severity_levels else original_sev

            rescored.append(finding)

        return rescored

    @staticmethod
    def _probabilistic_fusion(p_local: float, p_global: float, w_local: float = 0.7, w_global: float = 0.3) -> float:
        """
        Probabilistic logit fusion với Laplace smoothing để tránh cực trị 0/1.
        Công thức Bayes Log-Odds: fused = sigmoid(w_local * logit(p_local) + w_global * logit(p_global))
        """
        eps = 1e-4
        p1 = max(eps, min(1.0 - eps, float(p_local)))
        p2 = max(eps, min(1.0 - eps, float(p_global)))
        logit1 = math.log(p1 / (1.0 - p1))
        logit2 = math.log(p2 / (1.0 - p2))
        fused_logit = w_local * logit1 + w_global * logit2
        fused_p = 1.0 / (1.0 + math.exp(-fused_logit))
        return round(float(fused_p), 4)
