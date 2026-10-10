# Bộ bàn giao JuiceSec

## Dùng ứng dụng

Mở thư mục `JuiceSec-Analyzer`, đọc `README.md`. Python 3.10 trở lên, không cần thư viện Python ngoài.

```bash
cd JuiceSec-Analyzer
python evaluate.py
python app.py
```

Trên Windows có thể dùng `py -3` thay `python`. Mở http://127.0.0.1:5000.

`evidence` chứa kết quả thật trên dữ liệu mô phỏng. Không phải kết quả khai thác Juice Shop. Các kịch bản Juice Shop trong báo cáo cần chạy trên lab của người thực hiện để bổ sung bằng chứng.

## Nguồn tạo báo cáo

Thư mục `authoring` có dữ liệu và mã tạo báo cáo Word. Đây là công cụ biên soạn riêng, không phải dependency của ứng dụng. Cần Python cùng python-docx, Pillow và matplotlib. Môi trường tạo bản bàn giao là Linux, có font DejaVu Sans và font thay thế Times New Roman. Khi dùng font hoặc bộ chuyển PDF khác, phân trang có thể thay đổi.

Giữ hai thư mục `JuiceSec-Analyzer` và `authoring` cùng cấp. Chạy từ thư mục gốc đã giải nén:

```bash
python authoring/assemble.py
python authoring/render_book.py
```

Word được tạo trong `delivery`. Dùng Word hoặc LibreOffice để xuất PDF và kiểm tra lại phân trang. Bản PDF được bàn giao riêng đã được kiểm tra có 300 trang.

Muốn cập nhật kết quả thực nghiệm, chạy lại `evaluate.py`, sau đó dựng lại báo cáo. Lưu ý một số đoạn diễn giải và bảng tổng hợp hiện ghi rõ số liệu phiên bàn giao; cần rà lại đồng bộ khi thuật toán hoặc corpus thay đổi. Không tự thay các dòng trạng thái Juice Shop thành đã thực hiện nếu chưa có bằng chứng.

## Trước khi nộp

Điền trường, lớp, họ tên, mã sinh viên và giảng viên. Nếu đề bài yêu cầu thực nghiệm trực tiếp trên Juice Shop hoặc so sánh Windows/Linux, bổ sung dữ liệu đã chạy trên máy của bạn. Kiểm tra token và thông tin cá nhân trước khi đưa ảnh/log vào báo cáo.
