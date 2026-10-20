# Bộ bàn giao JuiceSec

## Dùng ứng dụng

Chạy trực tiếp từ thư mục gốc của repository (`2026-10-24devsecops-juiceshop-pipeline`). Yêu cầu Python 3.10 trở lên, không cần thư viện ngoài (Zero External Runtime Dependencies).

```bash
# 1. Chạy toàn bộ kiểm thử, đánh giá corpus, holdout và đo lường benchmark
python evaluate.py

# 2. Kiểm tra cổng chất lượng CI (Quality Gate)
python scan_gate.py --require-tests-pass --min-f1 0.85 --min-precision 0.85 --min-recall 0.85 --min-holdout-f1 0.85 --min-external-f1 0.50 --max-p95-ms 500

# 3. Khởi động Web UI phân tích (mở http://127.0.0.1:5000)
python app.py
```

Trên Windows có thể dùng `py -3` thay `python`. Mở http://127.0.0.1:5000 trong trình duyệt.

Thư mục `evidence/` chứa toàn bộ chứng cứ kiểm thử thực nghiệm:
- 63 bài Unit Test tự động (100% passed).
- Dữ liệu vi chuẩn tổng hợp nội bộ (synthetic micro-benchmarks): Corpus (40 snippets, F1=1.0000) và Holdout (26 snippets, F1=1.0000) dùng làm chốt chặn kiểm thử hồi quy (regression floor).
- Dữ liệu ngoài mẫu out-of-sample: External Corpus (40 snippets trích xuất từ CVE thực tế theo giao thức Zero-Tuning, đạt F1=0.5625; đối sánh với Semgrep đạt F1=0.6250 và Bandit đạt F1=0.7000 nhưng JuiceSec đạt tốc độ siêu tốc ~11.7ms so với Semgrep 7.27s và tiêu tốn ~705MB RAM).
- Phân tích sai số và 4 Failure Modes cấu trúc (`evidence/error_analysis.json`).
- Bằng chứng đối chuẩn baseline ba chiều (`evidence/appendix_c_benchmark.txt`).

Các kịch bản khai thác Juice Shop thật (`labs/juice_shop_exploits.py`) chạy trực tiếp trên Juice Shop cục bộ để bổ sung bằng chứng thực nghiệm độc lập:

```bash
# Chạy khai thác trên Juice Shop thật (port 3000) và khử nhạy cảm
python labs/juice_shop_exploits.py --target http://127.0.0.1:3000
python labs/redact_evidence.py evidence/

# Sinh phân tích ma trận nhầm lẫn và 4 failure modes
python labs/gen_error_analysis.py

# Đo chuẩn baseline đối sánh với Semgrep / Bandit
python labs/benchmark_baseline.py
```

Tài liệu học thuật kèm theo:
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md): Mô hình an toàn STRIDE, ranh giới tin cậy (Trust Boundaries) và kiểm thử an toàn.
- [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md): 5 giới hạn cấu trúc học thuật theo định lý Rice.
- [`docs/ERROR_ANALYSIS.md`](docs/ERROR_ANALYSIS.md): Phân tích sai số per-rule và 4 failure modes (shadowing, constant concat, dynamic dispatch, inter-procedural).

## Nguồn tạo báo cáo (Tùy chọn)

Thư mục `authoring/` (nếu có trong gói tài liệu biên soạn đầy đủ) chứa dữ liệu và mã tạo báo cáo Word bằng `python-docx`. Đây là công cụ biên soạn riêng biệt, không phải dependency của ứng dụng. Cần Python cùng python-docx, Pillow và matplotlib. Môi trường tạo bản bàn giao là Linux, có font DejaVu Sans và font thay thế Times New Roman. Khi dùng font hoặc bộ chuyển PDF khác, phân trang có thể thay đổi.

Khi có thư mục `authoring/` ở thư mục gốc:

```bash
python authoring/assemble.py
python authoring/render_book.py
```

Word được tạo trong `delivery`. Dùng Word hoặc LibreOffice để xuất PDF và kiểm tra lại phân trang. Bản PDF được bàn giao riêng đã được kiểm tra có 300 trang.

Muốn cập nhật kết quả thực nghiệm, chạy lại `evaluate.py`, sau đó dựng lại báo cáo. Lưu ý một số đoạn diễn giải và bảng tổng hợp hiện ghi rõ số liệu phiên bàn giao; cần rà lại đồng bộ khi thuật toán hoặc corpus thay đổi. Không tự thay các dòng trạng thái Juice Shop thành đã thực hiện nếu chưa có bằng chứng.

## Trước khi nộp

Điền trường, lớp, họ tên, mã sinh viên và giảng viên. Nếu đề bài yêu cầu thực nghiệm trực tiếp trên Juice Shop hoặc so sánh Windows/Linux, bổ sung dữ liệu đã chạy trên máy của bạn. Kiểm tra token và thông tin cá nhân trước khi đưa ảnh/log vào báo cáo.
