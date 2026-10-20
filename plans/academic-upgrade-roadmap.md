# LỘ TRÌNH NÂNG CẤP HỌC THUẬT (ACADEMIC UPGRADE ROADMAP)
## Định vị nâng tầm đồ án DevSecOps từ ~7/10 lên 8.5–9.0/10

---

### Bối cảnh & So sánh tương quan học thuật (So với bài phân tích DDoS 8/10)

Bài phân tích DDoS đạt điểm 8/10 nhờ vào **tính thực nghiệm vật lý vững chắc**: dữ liệu bắt gói mạng thực tế (`.pcap`), biểu đồ thông lượng (I/O Graphs từ Wireshark), và phân tích trực diện cơ chế giao thức tầng mạng L3/L4/L7. 

Ngược lại, đồ án [`juicesec`](juicesec/core.py) hiện đạt mức ~7/10: hệ thống đã có 63 unit test vượt qua, cô lập loopback an toàn, có cơ chế che giấu dữ liệu nhạy cảm ([`labs/redact_evidence.py`](labs/redact_evidence.py)), và đạt F1=1.0 trên tập [`data/corpus.json`](data/corpus.json) (40 mẫu) cùng [`data/holdout.json`](data/holdout.json) (26 mẫu). Tuy nhiên, **tập holdout hiện tại hoàn toàn là dữ liệu tự sinh (synthetic)**, chưa có đợt chạy trực tiếp độc lập trên phiên bản OWASP Juice Shop thực tế, chưa có đánh giá ngoài mẫu (out-of-sample), và chưa thừa nhận các điểm gãy kỹ thuật.

Để vươn lên mốc **8.5–9.0/10**, đồ án bắt buộc phải chuyển từ trạng thái *"công cụ tự phát biểu đạt 100% điểm"* sang **"công trình thực nghiệm nghiêm túc, có phương pháp luận đối chuẩn, trung thực về sai số và có khả năng tái lập độc lập"**.

---

### Bảng Ma Trận Lộ Trình Nâng Cấp (Prioritized by Grading Impact / Effort)

*Quy ước ROI:* 
- **Grading Impact**: Thang điểm từ 1 đến 5 sao ($\bigstar$).
- **Effort**: Độ phức tạp thực thi gồm ba mức tương đối: **S** (Small - cục bộ, ít phụ thuộc), **M** (Medium - đa module), **L** (Large - hạ tầng/toàn diện). Tuyệt đối không quy đổi ra thời gian ước lượng.
- **Priority Rank**: Xếp hạng ưu tiên theo tỷ số $\text{ROI} = \frac{\text{Impact}}{\text{Effort}}$.

| Hạng mục | Trụ cột học thuật | Concrete Deliverable | Exact File(s) to touch | Verification Command | Safe Academic Claim | Impact | Effort | Priority Rank (ROI) |
| :---: | :--- | :--- | :--- | :--- | :--- | :---: | :---: | :---: |
| **#1** | **Phân tích sai số FP/FN** (Trụ cột 3) | Script sinh phụ lục sai số, bảng ma trận nhầm lẫn Per-Rule Precision/Recall/F1, và 4 ca thất bại điển hình của JS analyzer | [`labs/gen_error_analysis.py`](labs/gen_error_analysis.py)<br>[`docs/ERROR_ANALYSIS.md`](docs/ERROR_ANALYSIS.md)<br>[`evidence/error_analysis.json`](evidence/error_analysis.json)<br>[`tests/test_core.py`](tests/test_core.py) | `python labs/gen_error_analysis.py`<br>`python -m unittest discover -s tests -v` | *"Analyzer minh bạch ranh giới kỹ thuật: do dùng intra-file heuristic token/AST, engine gặp FP ở lexical shadowing và FN ở dynamic property dispatch."* | $\bigstar\bigstar\bigstar\bigstar\bigstar$ (5) | **S** (1) | **1** (5.0) |
| **#2** | **Threat Model & Limitations** (Trụ cột 5) | Tài liệu mô hình đe dọa chuẩn STRIDE, ranh giới an toàn (Trust Boundaries) và 5 giới hạn cấu trúc học thuật (Academic Limitations) | [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)<br>[`docs/LIMITATIONS.md`](docs/LIMITATIONS.md)<br>[`README.md`](README.md)<br>[`VERIFY.md`](VERIFY.md) | `python -c "import pathlib; assert pathlib.Path('docs/THREAT_MODEL.md').is_file() and pathlib.Path('docs/LIMITATIONS.md').is_file(); print('Docs verified')"` | *"Hệ thống là PoC SAST/DAST gọn nhẹ trong ranh giới loopback, không thay thế scanner thương mại, bị giới hạn trước client-side rendering và dynamic obfuscation."* | $\bigstar\bigstar\bigstar\bigstar$ (4) | **S** (1) | **2** (4.0) |
| **#3** | **Đồng bộ hóa Báo cáo & Script** (Trụ cột 7) | Rà soát toàn bộ tài liệu, loại bỏ thuật ngữ phóng đại (100%, tuyệt đối), đồng bộ hóa số liệu thực tế với slide thuyết trình | [`README.md`](README.md)<br>[`SCRIPT_THUYT_TRINH_BTL.txt`](SCRIPT_THUYT_TRINH_BTL.txt)<br>[`sample_report_content.txt`](sample_report_content.txt)<br>[`HUONG_DAN_GOI_BAN_GIAO.md`](HUONG_DAN_GOI_BAN_GIAO.md) | `git grep -iE "(hoàn hảo|100%|tuyệt đối|zero false positive)" -- README.md SCRIPT_THUYT_TRINH_BTL.txt || echo "Clean"` | *"Báo cáo và kịch bản bảo vệ phản ánh chính xác kết quả đo đạc từ test harness, tuân thủ nguyên tắc khiêm tốn khoa học và liêm chính dữ liệu."* | $\bigstar\bigstar\bigstar\bigstar$ (4) | **S** (1) | **3** (4.0) |
| **#4** | **Làm cứng CI & Tái lập Artifacts** (Trụ cột 6) | Ghim cứng Docker digest, cấu hình upload artifact có mã băm SHA256, tách riêng pipeline test và DAST | [`.github/workflows/ci.yml`](.github/workflows/ci.yml)<br>[`.github/workflows/dast.yml`](.github/workflows/dast.yml)<br>[`docker-compose.yml`](docker-compose.yml)<br>[`VERIFY.md`](VERIFY.md) | `python scan_gate.py --require-tests-pass`<br>`sha256sum evidence/validation.json` | *"Toàn bộ artifact kiểm thử và bằng chứng DAST được tự động đóng gói, đánh dấu mã băm SHA-256 bất biến qua từng GitHub Actions workflow run."* | $\bigstar\bigstar\bigstar\bigstar$ (3.5) | **S** (1) | **4** (3.5) |
| **#5** | **Đánh giá Ngoài Mẫu (Out-of-sample)** (Trụ cột 2) | Bộ dữ liệu external gồm các snippet thực tế từ CVE công khai/open-source có provenance rõ ràng, giao thức Zero-Tuning không sửa rule | [`data/external_corpus.json`](data/external_corpus.json)<br>[`evaluate.py`](evaluate.py)<br>[`scan_gate.py`](scan_gate.py)<br>[`VERIFY.md`](VERIFY.md) | `python evaluate.py --external`<br>`python scan_gate.py --min-f1 0.85` | *"Đánh giá trên tập dữ liệu ngoài mẫu trích xuất từ CVE công khai theo giao thức đóng băng luật (Zero-Tuning) phản ánh năng lực tổng quát hóa thực tế của scanner."* | $\bigstar\bigstar\bigstar\bigstar\bigstar$ (5) | **M** (1.5) | **5** (3.33) |
| **#6** | **Thực nghiệm Juice Shop có thể tái lập** (Trụ cột 1) | Ghi nhận Docker image digest, thu thập raw HTTP traces (Request/Response có timestamp ISO-8601), tách biệt real target (port 3000) vs fixture | [`labs/juice_shop_exploits.py`](labs/juice_shop_exploits.py)<br>[`cli.py`](cli.py)<br>[`evidence/juice-exploits.json`](evidence/juice-exploits.json)<br>[`VERIFY.md`](VERIFY.md) | `python labs/juice_shop_exploits.py --target http://127.0.0.1:3000 --record-trace`<br>`test -f evidence/juice-exploits.json` | *"Dữ liệu DAST được bắt trực tiếp từ phiên bản OWASP Juice Shop cố định qua digest, tách bạch hoàn toàn với kết quả kiểm thử trên fixture mock server."* | $\bigstar\bigstar\bigstar\bigstar\bigstar$ (5) | **M** (2) | **6** (2.5) |
| **#7** | **Đối chuẩn Baseline với Semgrep & Bandit** (Trụ cột 4) | Script benchmark chạy Semgrep và Bandit trên cùng một tập corpus, bảng đối sánh 3 chiều: F1-score, Runtime latency, Resource footprint | [`labs/benchmark_baseline.py`](labs/benchmark_baseline.py)<br>[`evidence/appendix_c_benchmark.txt`](evidence/appendix_c_benchmark.txt)<br>[`requirements-dev.txt`](requirements-dev.txt)<br>[`VERIFY.md`](VERIFY.md) | `python labs/benchmark_baseline.py --corpus data/corpus.json`<br>`cat evidence/appendix_c_benchmark.txt` | *"JuiceSec đạt ưu thế vượt trội về độ trễ và zero runtime dependencies, trong khi Semgrep thể hiện độ phủ sâu hơn ở phân tích liên thủ tục."* | $\bigstar\bigstar\bigstar\bigstar\bigstar$ (5) | **M** (2) | **7** (2.5) |

---

### Chi Tiết Kỹ Thuật 7 Trụ Cột Nâng Cấp

#### 1. Thực nghiệm Juice Shop thực tế & Thu thập vết HTTP tái lập (Trụ cột 1)
- **Vấn đề giải quyết**: File [`evidence/juice-exploits.json`](evidence/juice-exploits.json) trước đây chưa ghi nhận `image_digest` của container, chưa tách rõ ràng kết quả tấn công thực nghiệm trên target port 3000 với mock server [`tests/fixture_server.py`](tests/fixture_server.py).
- **Cơ chế kỹ thuật**:
  - Trong [`labs/juice_shop_exploits.py`](labs/juice_shop_exploits.py), bổ sung bước truy vấn siêu dữ liệu môi trường: tự động đọc `docker inspect` để lấy `RepoDigests` (ví dụ `bkimminich/juice-shop@sha256:...`) và ghi vào header metadata của evidence file.
  - Cấu trúc lại trace collector trong [`_request()`](labs/juice_shop_exploits.py:71): ghi nhận toàn bộ HTTP request line, header, payload gửi đi và response code, response header, response body cùng timestamp (UTC) có gắn thẻ định danh rõ ràng: `"target_type": "REAL_JUICE_SHOP_INSTANCE"` so với `"target_type": "FIXTURE_SERVER"`.
  - Xuất kèm câu lệnh `curl` nguyên bản cho từng kịch bản để người chấm có thể tái lập tức thì ngoài terminal.

#### 2. Đánh giá Ngoài Mẫu (Out-of-sample) & Giao thức Zero-Tuning (Trụ cột 2)
- **Vấn đề giải quyết**: Tập [`data/corpus.json`](data/corpus.json) (40 mẫu) và [`data/holdout.json`](data/holdout.json) (26 mẫu) đều là mã nguồn tự biên tập nội bộ. Điểm F1=1.0 hiện tại là kết quả của việc tinh chỉnh rule trực tiếp trên tập mẫu này, không chứng minh được tính tổng quát hóa học thuật.
- **Cơ chế kỹ thuật**:
  - Tạo mới [`data/external_corpus.json`](data/external_corpus.json) gồm 40 đoạn mã độc lập (20 JS/TS, 20 Python) thu thập từ các nguồn CVE công khai (NodeGoat, PyGoat, SecLists). Mỗi mẫu có schema provenance nghiêm ngặt: `cve_id`, `repo_url`, `commit_sha`, `license`, `is_vulnerable`.
  - **Quy tắc Đóng Băng Luật (Zero-Tuning Freeze)**: Tính mã băm SHA-256 của [`juicesec/astscan.py`](juicesec/astscan.py) và [`juicesec/core.py`](juicesec/core.py) trước khi đánh giá. Nghiêm cấm sửa đổi regex hay AST visitor để ép điểm tăng trên tập external.
  - Cập nhật hàm [`measure()`](evaluate.py:63) trong [`evaluate.py`](evaluate.py) để đo lường tập external và ghi nhận kết quả thực tế (chấp nhận F1 đạt ~0.70–0.80 thay vì 1.0 ảo) vào [`evidence/validation.json`](evidence/validation.json).
  - Điều chỉnh [`scan_gate.py`](scan_gate.py): giữ ngưỡng `min-f1 0.85` cho synthetic corpus (chống suy thoái chức năng - regression test) và đặt ngưỡng thực tế `min-external-f1 0.65` cho out-of-sample.

#### 3. Phân tích Sai số Chi tiết & Failure Modes của Bộ Phân Tích JS (Trụ cột 3)
- **Vấn đề giải quyết**: Bộ phân tích JS trong [`juicesec/astscan.py`](juicesec/astscan.py) sử dụng token stream và regex heuristic. Việc không công khai các trường hợp nhận diện sai sẽ khiến hội đồng phản biện nghi ngờ tính xác thực.
- **Cơ chế kỹ thuật**:
  - Xây dựng module [`labs/gen_error_analysis.py`](labs/gen_error_analysis.py) tính toán ma trận nhầm lẫn chi tiết theo từng rule (`H-XSS`, `H-SQLI`, `H-IDOR`, `H-JWT`, `H-SEC-MISC`): TP, FP, TN, FN, Precision, Recall, F1.
  - Biên tập tài liệu [`docs/ERROR_ANALYSIS.md`](docs/ERROR_ANALYSIS.md) phân tích sâu 4 Failure Patterns cốt lõi do giới hạn kiến trúc:
    1. *Variable Aliasing & Lexical Shadowing (FP)*: Biến trùng tên trong inner block scope đã được sanitize nhưng scanner vẫn bắt nguồn từ outer scope.
    2. *Safe Constant Literal Concatenation (FP)*: Chuỗi nối là hằng số cố định (`const TABLE = 'users'`) nhưng bị regex nhận nhầm là injection.
    3. *Dynamic Property Dispatch (FN)*: Lệnh gọi hàm động `actions[dynamicKey](input)` làm đứt gãy call-tree tĩnh.
    4. *Inter-file / Inter-procedural Discontinuity (FN)*: Phân tích đơn file (intra-file) không lần theo được taint flow truyền qua module khác.

#### 4. Đo Chuẩn Đối Sánh Baseline với Semgrep & Bandit (Trụ cột 4)
- **Vấn đề giải quyết**: Đồ án chưa chứng minh được vị thế kỹ thuật của [`juicesec`](juicesec/core.py) so với các công cụ SAST công nghiệp đã có trong [`requirements-dev.txt`](requirements-dev.txt).
- **Cơ chế kỹ thuật**:
  - Viết harness [`labs/benchmark_baseline.py`](labs/benchmark_baseline.py) tự động trích xuất các mẫu code từ [`data/corpus.json`](data/corpus.json) và [`data/external_corpus.json`](data/external_corpus.json) vào thư mục tạm, sau đó kích hoạt song song 3 công cụ:
    - `juicesec` (chạy native Python)
    - `semgrep scan --config p/owasp-top-ten --config p/javascript --config p/python --json`
    - `bandit -r -f json` (trên code Python)
  - Ánh xạ nhãn phát hiện về chuẩn CWE (CWE-89, CWE-79, CWE-22, CWE-798).
  - Xuất bảng so sánh 3 chiều vào [`evidence/appendix_c_benchmark.txt`](evidence/appendix_c_benchmark.txt):
    1. *Độ chính xác*: Precision, Recall, F1 trên các bài lab Juice Shop.
    2. *Tài nguyên & Độ trễ*: Thời gian thực thi (Wall-clock ms), dung lượng bộ nhớ đỉnh (RAM MB), kích thước gói cài đặt.
    3. *Đặc tính kiến trúc*: Trọng lượng nhẹ, zero-runtime dependencies của JuiceSec đối chiếu với kiến trúc phân tích đồ thị sâu (CFG/DFG) của Semgrep.

#### 5. Mô hình Đe dọa (Threat Model) & Giới hạn Khoa học (Trụ cột 5)
- **Vấn đề giải quyết**: Thiếu tài liệu đặc tả ranh giới an toàn vận hành của scanner, dễ bị phản biện về rủi ro an toàn mạng khi chạy probe.
- **Cơ chế kỹ thuật**:
  - Tạo mới [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) phân tích theo mô hình STRIDE:
    - *Scope Constraints*: Ràng buộc loopback bất biến thông qua hàm [`validate_target()`](labs/juice_shop_exploits.py:44), cấm quét địa chỉ mạng công cộng.
    - *Trust Boundaries*: Scanner xem ứng dụng mục tiêu là untrusted; dữ liệu phản hồi được giới hạn dung lượng (`MAX_BODY = 65536`).
    - *Information Disclosure*: Mọi token, cookie, session đều đi qua bộ lọc mask nhạy cảm [`labs/redact_evidence.py`](labs/redact_evidence.py) trước khi lưu vết.
  - Tạo mới [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) liệt kê 5 giới hạn kỹ thuật cấu trúc: chỉ phân tích nội bộ đơn file (intra-file), không có headless browser để render DOM (CSR/SPA), không hỗ trợ de-obfuscation mã nguồn, active probe chỉ ở mức surface probing, và không kiểm soát an toàn bộ nhớ tầng native.

#### 6. Làm cứng CI/CD & Tính Tái Lập của Artifacts (Trụ cột 6)
- **Vấn đề giải quyết**: Khử bỏ hoàn toàn tính bất định (non-determinism) giữa các lần build trên GitHub Actions.
- **Cơ chế kỹ thuật**:
  - Trong [`docker-compose.yml`](docker-compose.yml) và [`.github/workflows/dast.yml`](.github/workflows/dast.yml), ghim cố định immutable digest: `bkimminich/juice-shop:v15.0.0@sha256:...`.
  - Cấu hình step kiểm tra tính toàn vẹn runtime trong [`.github/workflows/ci.yml`](.github/workflows/ci.yml): xác nhận [`requirements.txt`](requirements.txt) không chứa bất kỳ dependency bên ngoài nào bằng đoạn script assertion tự động.
  - Đóng gói toàn bộ artifacts trong thư mục `evidence/` kèm mã băm SHA-256 được xuất bản trực tiếp vào GitHub Actions Artifacts sau mỗi lần chạy.

#### 7. Đồng bộ hóa Báo cáo, Kịch bản Thuyết trình và Tài liệu (Trụ cột 7)
- **Vấn đề giải quyết**: Ngôn từ trong các tài liệu hiện tại có thể gây hiểu nhầm về một công cụ "hoàn hảo bắt được mọi lỗi".
- **Cơ chế kỹ thuật**:
  - Cập nhật [`README.md`](README.md): thay thế các câu từ tuyệt đối bằng định nghĩa phạm vi chuẩn xác: *"Engine SAST/DAST quy tắc mẫu nhắm vào tập con xác thực của OWASP Top 10 (SQLi, Reflected XSS, IDOR, JWT)"*.
  - Sửa đổi [`SCRIPT_THUYT_TRINH_BTL.txt`](SCRIPT_THUYT_TRINH_BTL.txt): viết lại phần mở đầu và kết luận, định vị JuiceSec như một nghiên cứu thực nghiệm tối ưu hóa kiểm thử bảo mật nhanh (Fast-feedback Pre-commit Gate) cho môi trường DevSecOps.
  - Bổ sung vào [`VERIFY.md`](VERIFY.md) quy trình xác minh 1 lệnh (One-command Reproduction) cho người chấm thi.

---

### Phân Kỳ Triển Khai (3 Giai Đoạn Thực Thi)

- **Giai đoạn 1: Liêm chính Học thuật & Tối ưu Báo cáo (Quick Wins)**
  - Tập trung triển khai các hạng mục có ROI cao nhất (#1, #2, #3): xây dựng phụ lục sai số [`docs/ERROR_ANALYSIS.md`](docs/ERROR_ANALYSIS.md), hoàn thiện [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md), [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md), và dọn dẹp các tuyên bố phóng đại trong [`README.md`](README.md) cùng [`SCRIPT_THUYT_TRINH_BTL.txt`](SCRIPT_THUYT_TRINH_BTL.txt).
- **Giai đoạn 2: Bằng chứng Thực nghiệm & Đánh giá Độc lập**
  - Thực thi các hạng mục nền tảng (#4, #5, #6): xây dựng [`data/external_corpus.json`](data/external_corpus.json) có provenance, nâng cấp [`evaluate.py`](evaluate.py) với cờ `--external`, chạy thực tế kịch bản [`labs/juice_shop_exploits.py`](labs/juice_shop_exploits.py) trên Docker Juice Shop để lưu vết HTTP nguyên bản, và cấu hình CI gate trung thực.
- **Giai đoạn 3: Nghiên cứu Đối sánh Chuyên sâu**
  - Hoàn thiện bài toán đối sánh (#7): viết [`labs/benchmark_baseline.py`](labs/benchmark_baseline.py), chạy thực nghiệm so sánh với Semgrep và Bandit, xuất dữ liệu vào [`evidence/appendix_c_benchmark.txt`](evidence/appendix_c_benchmark.txt) và hoàn thiện chương đánh giá hiệu năng trong báo cáo.

---

### Bộ Quy Tắc Chống Ngụy Tạo Số Liệu (Anti-Fabrication Guardrails)

Nhằm đảm bảo điểm số đạt từ 8.5–9.0/10 tuyệt đối không bị hoài nghi trong quá trình bảo vệ, mọi thành viên và module đều phải tuân thủ 4 nguyên tắc sau:

1. **Nguyên tắc "Không Điểm Số Hoàn Hảo" (Zero-Perfection Rule)**:
   - Nghiêm cấm đưa ra số liệu Precision=1.0 hoặc Recall=1.0 trên tập dữ liệu ngoài mẫu ([`data/external_corpus.json`](data/external_corpus.json)). Bất kỳ mô hình phân tích tĩnh nào trong thực tế đều phải chấp nhận sự đánh đổi (trade-off) giữa FP và FN.
2. **Bảo tồn Dữ liệu Thô Tuyệt đối (Raw Preservation)**:
   - Mọi bảng số liệu trong báo cáo và slide thuyết trình phải được trích xuất tự động bằng script từ file raw JSON (`evidence/*.json`). Không chỉnh sửa số liệu thủ công hoặc can thiệp trung gian bằng phần mềm ngoài.
3. **Truy nguyên Nguồn gốc Dữ liệu (Provenance Chain)**:
   - Từng mẫu code trong tập external phải có commit SHA và URL gốc trỏ về kho lưu trữ CVE công khai. File kết quả phải lưu kèm thời gian thực thi (UTC) và mã băm SHA-256 của file rule tại thời điểm quét.
4. **Minh bạch Điểm Gãy Kỹ thuật (Failure Transparency)**:
   - Các trường hợp scanner đoán sai hoặc kịch bản probe không thành công phải được công khai trong phụ lục sai số và phân loại nguyên nhân rõ ràng, biến điểm yếu thành minh chứng cho tính trung thực và phương pháp nghiên cứu khoa học.
