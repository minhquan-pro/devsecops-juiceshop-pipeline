# JuiceSec Analyzer 1.2

Bản mẫu giáo dục hỗ trợ đề tài PortSwigger và OWASP Juice Shop. Có năm phân hệ: tri thức, HTTP probe & OpenAPI Fuzzer, rà soát source bằng AST liên thủ tục (Inter-procedural Taint) cho Python và bộ theo vết token/regex cho JS-like, script khai thác Juice Shop thật, và báo cáo JSON/HTML. Kèm một pipeline DevSecOps chạy kiểm thử, cổng chất lượng và quét bảo mật trên chính công cụ này.

## Điểm mới ở 1.2

- **SAST Lõi Sâu: Inter-procedural Taint Analysis cho Python**: Nâng cấp `juicesec/astscan.py` với cấu trúc đồ thị lời gọi hàm (Call Graph) và tóm tắt hàm (Function Summaries) 2-pass. Theo vết dữ liệu bẩn (taint tracking) xuyên qua hàm con, đa tầng gọi (multi-hop calls), giá trị trả về (`return`) và phương thức lớp (`class method`). Khắc phục Failure Mode 4 (Inter-procedural Discontinuity), nâng F1 trên tập CVE ngoại lai (`data/external_corpus.json`) từ 0.56 lên **0.6471**.
- **DAST Lõi Sâu: Dynamic OpenAPI / Swagger Fuzzer**: Nâng cấp `juicesec/core.py` với tính năng tự động khám phá endpoint động từ `/api-docs/` (chuẩn OpenAPI v2 và v3), bóc tách kiểu tham số và tự động sinh payload fuzzing (biên giá trị `0`, `-1`, max/min integer; ép sai kiểu; SQLi, XSS, Path Traversal, Command Injection, LDAP, NoSQL) thay vì chỉ dùng danh sách path tĩnh. Bổ sung cờ `--openapi-fuzz` cho CLI và Web API.
- **Engine SAST lai & Phân tích Sai số Minh bạch**: `juicesec/astscan.py` kết hợp phân tích cú pháp `ast` chuẩn (Python) và bộ theo vết taint/token cho JavaScript/Node.js (intra-procedural heuristic). Đạt F1=1.0 trên tập vi chuẩn tổng hợp nội bộ (corpus 40 mẫu, holdout 26 mẫu) đóng vai trò chốt chặn hồi quy (regression floor). Đồng thời, hệ thống minh bạch hóa các Failure Modes và cung cấp báo cáo chi tiết tại [`docs/ERROR_ANALYSIS.md`](docs/ERROR_ANALYSIS.md).
- **Mô hình Đe dọa & Giới hạn Cấu trúc**: Bổ sung mô hình an toàn chuẩn STRIDE tại [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) và phân tích 5 giới hạn kỹ thuật theo lý thuyết khả toán (Rice's Theorem) tại [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md).
- **Khai thác thật & Tái lập Độc lập**: `labs/juice_shop_exploits.py` chạy các kịch bản SQLi, IDOR và JWT trực tiếp lên Juice Shop với Docker image digest cố định (`v15.0.0@sha256:721fc2cf0de50f11181be391152a5509c25fb13d0a21852277d13e3871dd6cf2`), phân định rạch ròi vết HTTP thực nghiệm và mock fixture server.
- **Pipeline DevSecOps Chặt chẽ**: Tự động hóa CI qua `.github/workflows/ci.yml` và `dast.yml` với kiểm tra toàn vẹn mã băm SHA-256 (`evidence/checksums.sha256`) và ràng buộc zero third-party runtime dependencies.

## Chạy nhanh

Cần Python 3.10 trở lên; không cần thư viện Python ngoài cho phần chạy. Đã kiểm tra tự động bằng Python 3.12.14 trên Linux và Python 3.14.7 trên Windows.

Windows PowerShell, mở trong thư mục dự án:

```powershell
py -3 -m venv .venv
.venv\Scripts\python.exe evaluate.py
.venv\Scripts\python.exe app.py
```

Linux:

```bash
python3 -m venv .venv
.venv/bin/python evaluate.py
.venv/bin/python app.py
```

Mở **http://127.0.0.1:5000**. Phải dùng đúng `127.0.0.1`, vì server kiểm tra Host và Origin. Nếu cổng bận, dùng `python app.py --port 5001` rồi mở đúng cổng đó. Nhấn Ctrl+C để dừng.

## Juice Shop

Cài Docker theo tài liệu chính thức của hệ điều hành. Tệp Compose chọn **v15.0.0** để bám companion guide tương thích; không phải bản mới nhất. Từ thư mục dự án:

```bash
docker compose up -d
docker compose ps
docker compose logs --tail 100 juice-shop
docker image inspect bkimminich/juice-shop:v15.0.0
```

Mở http://127.0.0.1:3000. Lưu image ID/digest, Docker version và hệ điều hành vào hồ sơ thực nghiệm. Mục tiêu có chủ đích chứa lỗi, chỉ publish loopback. Không gắn thư mục cá nhân vào container. Khi xong và đã lưu bằng chứng:

```bash
docker compose down
```

Phiên kiểm thử này **đã chạy Juice Shop v15.0.0 thật** bằng Docker trên Windows: `labs/juice_shop_exploits.py` tái hiện được 2/3 kịch bản (SQLi bypass và IDOR; JWT bị từ chối đúng vì Juice Shop dùng RS256). Bằng chứng nằm ở `evidence/juice-exploits.json`. Vẫn không coi các tệp fixture hoặc dữ liệu mechanism demo là kết quả exploit Juice Shop.

## Khai thác thật trên Juice Shop

Sau khi `docker compose up -d` và Juice Shop đã sẵn sàng:

```bash
python labs/juice_shop_exploits.py --target http://127.0.0.1:3000 --out evidence/juice-exploits.json
python labs/redact_evidence.py evidence/
```

Script chỉ nhận đích loopback, chỉ dùng thư viện chuẩn, và khử nhạy cảm token trước khi ghi. Ba kịch bản: SQLi bypass `POST /rest/user/login`; IDOR đọc giỏ hàng của người khác; giả mạo JWT bằng `alg:none` và HS256 với secret yếu. Mỗi kịch bản ghi request, mã phản hồi và kết luận `vulnerable`, `not_reproduced` hoặc `inconclusive` khi chưa đủ bằng chứng.

## Pipeline DevSecOps

`.github/workflows/ci.yml` chạy khi push/PR: kiểm thử, `evaluate.py`, cổng chất lượng `scan_gate.py` (ngưỡng F1/precision/recall/holdout/p95), bandit, semgrep, gitleaks, build image rồi trivy. `.github/workflows/dast.yml` dựng Juice Shop thật, chạy scan và exploit, khử nhạy cảm rồi lưu artifact.

Chạy cổng chất lượng tại máy:

```bash
python evaluate.py
python scan_gate.py --require-tests-pass --min-f1 0.85 --min-precision 0.85 --min-recall 0.85 --min-holdout-f1 0.85 --max-p95-ms 500
```

Build và kiểm tra image công cụ:

```bash
docker build -t juicesec-analyzer .
docker run --detach --name juicesec juicesec-analyzer app.py --port 5000
# Server chỉ bind 127.0.0.1 và kiểm tra Host, nên kiểm tra từ bên trong container:
docker exec juicesec python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:5000/api/session').read().decode())"
docker exec juicesec python -m unittest discover -s tests
docker stop juicesec
```

Do giới hạn loopback-only, không publish cổng ra ngoài cho image này. Muốn dùng UI từ máy, chạy trực tiếp `python app.py` trên máy, không qua Docker.


## Dùng giao diện

1. Kiểm tra HTTP: giữ đích loopback; mặc định gửi 5 GET. Checkbox thêm đúng một probe dấu nháy vào tìm kiếm.
2. Rà soát mã: dán mã đã loại secret; tên tệp chỉ là nhãn, không được mở trên server.
3. Kiến thức: tìm theo tên/CWE/nội dung.
4. Kết quả: đọc evidence và remediation; tải JSON/HTML. Mọi finding là `needs_review`.

Báo cáo gần nhất chỉ nằm trong RAM và bị thay khi phân tích tiếp. Một người dùng trên một server. Không có lịch sử, đăng nhập, nhiều tenant hay database.

## Chạy khi chưa có Juice Shop

Terminal thứ nhất:

```bash
python -m tests.fixture_server
```

Terminal thứ hai:

```bash
python cli.py --target http://127.0.0.1:3001 --active --out evidence/local-fixture.json
```

Fixture là server mô phỏng, không phải Juice Shop. Tắt bằng Ctrl+C.

## Dùng CLI

```bash
python cli.py --target http://127.0.0.1:3000 --out evidence/juice-baseline.json
python cli.py --target http://127.0.0.1:3000 --active --out evidence/juice-error-probe.json
python cli.py --source path/to/example.js --out evidence/source-report.json
python labs/mechanism_demos.py
python labs/juice_shop_exploits.py --target http://127.0.0.1:3000
```

CLI tạo cả JSON và HTML. Không dùng dữ liệu tài khoản thật hoặc mã chứa secret. Trường source snippet có thể xuất vào báo cáo.

## Xác minh

```bash
python -m unittest discover -s tests -v
python evaluate.py
```

`evaluate.py` chạy toàn bộ bài test unit, corpus 40 mẫu, holdout 26 mẫu và 20 vòng benchmark HTTP fixture sau một warm-up. Kết quả trong evidence:

- `tests.txt`: kết quả từng test.
- `validation.json`: môi trường, thống kê, provenance (hash SHA-256 dataset, kiểm tra schema/trùng lặp), engine và thời gian thô.
- `corpus-results.json`: nhãn, dự đoán, TP/FP/TN/FN của từng mẫu corpus.
- `holdout-results.json`: như trên cho tập holdout tổng hợp kiểm thử hồi quy.
- `fixture-report.json` và `.html`: báo cáo mô phỏng.
- `juice-exploits.json`: bằng chứng khai thác thật trên Juice Shop (đã khử nhạy cảm).
- `juice-baseline.json` / `juice-error-probe.json`: scan thật trên Juice Shop.
- `mechanism-demos.json`: SQL, quyền truy cập, đường dẫn và chữ ký HMAC tự xây dựng.

**Corpus nội bộ (40 mẫu)**: TP=19, FP=0, TN=21, FN=0 → Precision=1.0000, Recall=1.0000, F1=1.0000.
**Holdout nội bộ (26 mẫu, chốt chặn hồi quy)**: TP=13, FP=0, TN=13, FN=0 → Precision=1.0000, Recall=1.0000, F1=1.0000.
**Đánh giá ngoài mẫu (Out-of-sample External Corpus, 40 mẫu từ CVE công khai theo giao thức Zero-Tuning)**: Được đo đạc độc lập tại [`data/external_corpus.json`](data/external_corpus.json), phản ánh năng lực tổng quát hóa thực tế mà không tinh chỉnh quy tắc ép điểm.
**Baseline 1.0 tham chiếu cũ**: TP=11, FP=7, TN=14, FN=8 → Precision=61.11%, Recall=57.89%, F1=59.46%.

Đơn vị đo là snippet mã nguồn (nhị phân có/không ít nhất một finding). Nhóm nghiên cứu khẳng định các tập nội bộ là vi chuẩn tổng hợp có chủ đích (curated synthetic benchmark), không đại diện cho toàn bộ các trường hợp phức tạp ngoài thực tế. Mọi phân tích sai số và đánh đổi học thuật được trình bày chi tiết tại [`docs/ERROR_ANALYSIS.md`](docs/ERROR_ANALYSIS.md) và [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md).

## Giới hạn kỹ thuật

- Regex theo dòng (đã bỏ dòng chỉ có chú thích) kết hợp AST cho Python và bộ theo vết dòng chảy dựa trên token/regex cho JS-like (không phải parser ECMAScript AST đầy đủ). Engine JS-like theo vết taint đơn giản; không hỗ trợ luồng liên hàm (inter-procedural), closure lồng, destructuring hoặc callback bất đồng bộ.
- Tập holdout là bộ vi chuẩn tổng hợp nội bộ (synthetic micro-benchmark) phục vụ kiểm định hồi quy, không phải tập dữ liệu bên ngoài thu thập độc lập.
- Không có crawl, không chạy JS trong trình duyệt; DAST gửi 5 đường dẫn cố định và thêm đúng một probe dấu nháy.
- Mục tiêu chỉ HTTP loopback; không userinfo/path/query/fragment trong origin. localhost được pin IP; không redirect.
- Body tối đa 262144 byte, source tối đa 200000 byte UTF-8, findings tối đa 200.
- Một số kịch bản khai thác gắn với phiên bản Juice Shop cụ thể (v15.0.0). JWT RS256 khiến hai cách giả mạo đơn giản bị từ chối; đó là kết quả âm trung thực, không phải lỗi script.
- Không có finding không có nghĩa an toàn. Lỗi SQL không có nghĩa đã xác nhận SQLi; cần script khai thác mới kết luận.
- Server chuẩn Python dành cho lab, không triển khai public.

## Cấu trúc

`app.py` server; `cli.py` dòng lệnh; `evaluate.py` số liệu; `scan_gate.py` cổng chất lượng; `juicesec/core.py` lõi HTTP + SAST; `juicesec/astscan.py` AST/taint cho Python và theo vết token/regex cho JS-like; `static/` giao diện; `data/` tri thức, corpus, holdout; `tests/` kiểm thử; `labs/` khai thác thật và khử nhạy cảm; `evidence/` số liệu đã chạy; `.github/workflows/` pipeline; `Dockerfile` image công cụ.

## Hồ sơ cần bổ sung khi làm lab thật

Với mỗi case, lưu tag/commit hoặc image digest, thời gian, trạng thái trước, request cơ sở, đối chứng, response đã khử nhạy cảm, ảnh thật nếu cần, đoạn mã liên quan, bản vá và kết quả hồi quy. Báo cáo 300 trang có quy trình cho bảy case chính. Không điền kết quả kỳ vọng vào cột kết quả quan sát.
