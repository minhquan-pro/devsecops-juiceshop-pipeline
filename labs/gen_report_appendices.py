#!/usr/bin/env python3
"""Generate Report Appendices B and C from data and evidence artifacts.

This script reproduces the exact appendix sections cited in the academic report:
- Appendix B: Corpus & Holdout validation test cases, predictions, and confusion matrix cells.
- Appendix C: Performance benchmark metrics and validation summary.
"""

from pathlib import Path
import json
import sys

ROOT = Path(__file__).resolve().parent.parent

def load_json(rel_path):
    p = ROOT / rel_path
    if not p.exists():
        print(f"Warning: {rel_path} does not exist.", file=sys.stderr)
        return None
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)

def format_appendix_b():
    corpus = load_json("evidence/corpus-results.json") or []
    holdout = load_json("evidence/holdout-results.json") or []
    external = load_json("evidence/external-results.json") or []

    lines = []
    lines.append("PHỤ LỤC B: TOÀN BỘ MẪU THỬ NGHIỆM CORPUS, HOLDOUT VÀ ĐỐI CHỨNG DỰ ĐOÁN\n")
    lines.append("Mỗi mẫu dưới đây được sinh trực tiếp từ data/ và evidence/ bằng labs/gen_report_appendices.py, "
                 "nên cột nhãn, dự đoán và quy tắc khớp luôn trùng khớp với số liệu ở Chương 5 và với artifact đã công bố.\n")

    lines.append("=" * 80)
    lines.append("B.1 TẬP CORPUS KIỂM CHUẨN (40 MẪU)\n")
    for idx, item in enumerate(corpus, 1):
        gt = "Vulnerable" if item.get("positive") else "Safe"
        pred = "Vulnerable" if item.get("predicted") else "Safe"
        correct = "Đúng" if item.get("positive") == item.get("predicted") else "Sai"
        cat = item.get("category", "").upper()
        rules = ", ".join(item.get("rule_ids", [])) or "Không có (An toàn)"
        
        lines.append(f"B.1.{idx} Mẫu Thử Nghiệm #{idx}: {item.get('id')}")
        lines.append(f"- Mã định danh: {item.get('id')}")
        lines.append(f"- Nhãn Thực tế (Ground Truth): **{gt}**")
        lines.append(f"- Dự đoán của JuiceSec Analyzer: **{pred}** ({correct})")
        lines.append(f"- Ô ma trận nhầm lẫn: {cat}")
        lines.append(f"- Quy tắc khớp (rule_ids): {rules}")
        lines.append(f"- Lý do gán nhãn: {item.get('rationale', '')}")
        lines.append("Đoạn mã Nguồn Kiểm chuẩn (Source Code):")
        for line_no, code_line in enumerate(item.get("source", "").splitlines(), 1):
            lines.append(f"  {line_no:3d} | {code_line}")
        lines.append("")

    lines.append("=" * 80)
    lines.append("B.2 TẬP HOLDOUT ĐỘC LẬP (26 MẪU)\n")
    for idx, item in enumerate(holdout, 1):
        gt = "Vulnerable" if item.get("positive") else "Safe"
        pred = "Vulnerable" if item.get("predicted") else "Safe"
        correct = "Đúng" if item.get("positive") == item.get("predicted") else "Sai"
        cat = item.get("category", "").upper()
        rules = ", ".join(item.get("rule_ids", [])) or "Không có (An toàn)"

        lines.append(f"B.2.{idx} Mẫu Holdout #{idx}: {item.get('id')}")
        lines.append(f"- Mã định danh: {item.get('id')}")
        lines.append(f"- Nhãn Thực tế (Ground Truth): **{gt}**")
        lines.append(f"- Dự đoán của JuiceSec Analyzer: **{pred}** ({correct})")
        lines.append(f"- Ô ma trận nhầm lẫn: {cat}")
        lines.append(f"- Quy tắc khớp (rule_ids): {rules}")
        lines.append(f"- Lý do gán nhãn: {item.get('rationale', '')}")
        lines.append("Đoạn mã Nguồn Kiểm chuẩn (Source Code):")
        for line_no, code_line in enumerate(item.get("source", "").splitlines(), 1):
            lines.append(f"  {line_no:3d} | {code_line}")
        lines.append("")

    if external:
        lines.append("=" * 80)
        lines.append("B.3 TẬP OUT-OF-SAMPLE CVE ĐỐI CHỨNG NGOÀI (40 MẪU)\n")
        for idx, item in enumerate(external, 1):
            gt = "Vulnerable" if item.get("positive") else "Safe"
            pred = "Vulnerable" if item.get("predicted") else "Safe"
            correct = "Đúng" if item.get("positive") == item.get("predicted") else "Sai"
            cat = item.get("category", "").upper()
            rules = ", ".join(item.get("rule_ids", [])) or "Không có (An toàn)"
            cve = item.get("cve_id", "N/A")

            lines.append(f"B.3.{idx} Mẫu Ngoài #{idx}: {item.get('id')} [{cve}]")
            lines.append(f"- Mã định danh: {item.get('id')} | CVE: {cve}")
            lines.append(f"- Nhãn Thực tế (Ground Truth): **{gt}**")
            lines.append(f"- Dự đoán của JuiceSec Analyzer: **{pred}** ({correct})")
            lines.append(f"- Ô ma trận nhầm lẫn: {cat}")
            lines.append(f"- Quy tắc khớp (rule_ids): {rules}")
            lines.append(f"- Lý do gán nhãn: {item.get('rationale', '')}")
            lines.append("Đoạn mã Nguồn Kiểm chuẩn (Source Code):")
            for line_no, code_line in enumerate(item.get("source", "").splitlines(), 1):
                lines.append(f"  {line_no:3d} | {code_line}")
            lines.append("")

    return "\n".join(lines)

def format_appendix_c():
    app_c_path = ROOT / "evidence" / "appendix_c_benchmark.txt"
    if app_c_path.is_file():
        return app_c_path.read_text(encoding="utf-8")

    val = load_json("evidence/validation.json") or {}
    lines = []
    lines.append("PHỤ LỤC C: BẢNG DỮ LIỆU ĐO LƯỜNG HIỆU NĂNG, LOGS HTTP VÀ BENCHMARK CHI TIẾT\n")
    lines.append("Toàn bộ nội dung dưới đây sinh trực tiếp từ thư mục evidence/ bằng labs/gen_report_appendices.py, "
                 "nên khớp chính xác với artifact đã công bố của JuiceSec Analyzer 1.1.\n")
    lines.append("C.1 Validation Benchmark Results (validation.json)")
    lines.append("Trích xuất C.1 Validation Benchmark Results (validation.json):")
    lines.append(json.dumps(val, indent=2, ensure_ascii=False))
    lines.append("")
    return "\n".join(lines)

def main():
    out_dir = ROOT / "evidence"
    out_dir.mkdir(exist_ok=True)
    
    app_b = format_appendix_b()
    app_c = format_appendix_c()
    
    out_b_path = out_dir / "appendix_b_samples.txt"
    out_c_path = out_dir / "appendix_c_benchmark.txt"
    
    out_b_path.write_text(app_b, encoding="utf-8")
    out_c_path.write_text(app_c, encoding="utf-8")
    
    print(f"Generated Appendix B at: {out_b_path}")
    print(f"Generated Appendix C at: {out_c_path}")

if __name__ == "__main__":
    main()
