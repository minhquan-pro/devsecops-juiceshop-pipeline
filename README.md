# JuiceSec Analyzer 1.0

Bản mẫu giáo dục hỗ trợ đề tài PortSwigger và OWASP Juice Shop. Có bốn phân hệ: tri thức, HTTP probe cục bộ, rà soát regex source và báo cáo JSON/HTML.

## Chạy nhanh

Cần Python 3.10 trở lên; không cần thư viện Python ngoài. Đã kiểm tra tự động bằng Python 3.12.14 trên Linux. Chưa kiểm tra trực tiếp Windows hoặc trình duyệt trong môi trường biên soạn.

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

Phiên biên soạn **không có Docker và chưa chạy Juice Shop**. Không coi các tệp fixture hoặc dữ liệu mechanism demo là kết quả exploit Juice Shop.

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
```

CLI tạo cả JSON và HTML. Không dùng dữ liệu tài khoản thật hoặc mã chứa secret. Trường source snippet có thể xuất vào báo cáo.

## Xác minh

```bash
python -m unittest discover -s tests -v
python evaluate.py
```

`evaluate.py` chạy 40 test, corpus 40 mẫu và 20 vòng benchmark HTTP fixture sau một warm-up. Kết quả trong evidence:

- `tests.txt`: kết quả từng test.
- `validation.json`: môi trường, thống kê và thời gian thô.
- `corpus-results.json`: nhãn, dự đoán, TP/FP/TN/FN của từng mẫu.
- `fixture-report.json` và `.html`: báo cáo mô phỏng.
- `mechanism-demos.json`: SQL, quyền truy cập, đường dẫn và chữ ký HMAC tự xây dựng.

Ở bản được bàn giao: TP=11, FP=7, TN=14, FN=8, precision=61.11%, recall=57.89%, F1=59.46%. Đơn vị là snippet có/không ít nhất một finding. Corpus có giả định ngữ cảnh; đọc rationale. Đây không phải đánh giá ngoài mẫu hoặc tỷ lệ phát hiện trên Juice Shop.

## Giới hạn kỹ thuật

- Regex theo dòng, không AST/taint/crawl/browser. Dương tính giả ở chú thích và hằng; bỏ sót alias, biến trung gian, IDOR, CSRF.
- Mục tiêu chỉ HTTP loopback; không userinfo/path/query/fragment trong origin. localhost được pin IP; không redirect.
- Body tối đa 262144 byte, source tối đa 200000 byte UTF-8, findings tối đa 200. Chưa có cờ báo khi SAST chạm ngưỡng.
- Timeout là socket operation, không deadline tổng cứng; chưa hỗ trợ giải nén phản hồi tùy ý.
- Không có finding không có nghĩa an toàn. HTTP 200 không có nghĩa endpoint lộ. Lỗi SQL không có nghĩa đã xác nhận SQLi.
- Server chuẩn Python dành cho lab, không triển khai public. Origin/CSRF không thay hệ thống xác thực nhiều người dùng.
- Đã kiểm thử API; chưa có xác minh hiển thị tự động trên trình duyệt trong môi trường tạo gói.

## Cấu trúc

`app.py` server; `cli.py` dòng lệnh; `juicesec/core.py` lõi; `static/` giao diện; `data/` tri thức/corpus; `tests/` kiểm thử; `labs/` ví dụ cơ chế; `evidence/` số liệu đã chạy.

## Hồ sơ cần bổ sung khi làm lab thật

Với mỗi case, lưu tag/commit hoặc image digest, thời gian, trạng thái trước, request cơ sở, đối chứng, response đã khử nhạy cảm, ảnh thật nếu cần, đoạn mã liên quan, bản vá và kết quả hồi quy. Báo cáo 300 trang có quy trình cho bảy case chính. Không điền kết quả kỳ vọng vào cột kết quả quan sát.
