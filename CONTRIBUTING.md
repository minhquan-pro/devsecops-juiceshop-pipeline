# Hướng Dẫn Đóng Góp

## Quy Trình Phát Triển

### 1. Thiết Lập Môi Trường

```bash
# Clone repository
git clone <repository-url>
cd devsecops-juiceshop-pipeline

# Cài đặt pre-commit hooks (khuyến nghị)
pip install pre-commit
pre-commit install

# Chạy kiểm tra cục bộ
python -m pytest tests/
python scan_gate.py --require-tests-pass
```

### 2. Quy Ước Nhánh (Branching Strategy)

```
main                    # Nhánh chính, production-ready
├── feature/tên-tính-năng  # Tính năng mới
├── fix/mô-tả-lỗi         # Sửa lỗi
├── docs/cập-nhật-tài-liệu # Cập nhật documentation
└── refactor/cải-thiện    # Refactoring code
```

**Ví dụ:**
- `feature/add-sbom-generation`
- `fix/scan-gate-timeout`
- `docs/update-api-examples`

### 3. Quy Ước Commit (Conventional Commits)

```
<type>: <mô tả ngắn gọn>

[Mô tả chi tiết tùy chọn]

[Footer: Breaking Changes, Issues liên quan]
```

**Types:**
- `feat`: Tính năng mới
- `fix`: Sửa lỗi
- `docs`: Cập nhật tài liệu
- `style`: Format code (không ảnh hưởng logic)
- `refactor`: Refactor code
- `test`: Thêm hoặc sửa tests
- `chore`: Cập nhật build scripts, dependencies

**Ví dụ:**
```
feat: thêm hỗ trợ quét SBOM tự động

Tích hợp cyclonedx-python để sinh SBOM từ dependencies
và lưu vào thư mục evidence/ sau mỗi lần quét.

Closes #42
```

### 4. Quy Trình Pull Request

#### Trước khi tạo PR:

```bash
# Chạy tất cả kiểm tra
python -m pytest tests/ -v
python scan_gate.py --require-tests-pass

# Kiểm tra code style (nếu cài đặt ruff)
ruff check .

# Đảm bảo không có secret bị leak
git secrets --scan || echo "Cài đặt git-secrets để bảo vệ tốt hơn"
```

#### Tiêu Đề PR:

Format giống commit message:
```
feat: thêm export báo cáo dạng PDF
fix: sửa lỗi timeout khi quét Juice Shop
```

#### Mô Tả PR:

```markdown
## Tóm tắt
[Mô tả ngắn gọn thay đổi]

## Loại thay đổi
- [ ] Tính năng mới (feature)
- [ ] Sửa lỗi (bug fix)
- [ ] Breaking change (thay đổi API/behavior)
- [ ] Cập nhật tài liệu

## Đã kiểm tra
- [ ] Tất cả tests đều pass
- [ ] Scan gate pass với ngưỡng hiện tại
- [ ] Không có secret bị leak
- [ ] Đã cập nhật documentation nếu cần

## Screenshots/Logs
[Nếu có thay đổi UI hoặc output quan trọng]
```

### 5. Chuẩn Code Style

#### Python:
- Tuân thủ PEP 8
- Type hints cho tất cả public functions
- Docstrings cho modules, classes, và public methods
- Độ dài dòng: tối đa 100 ký tự

```python
def analyze_response(record: dict) -> list[dict]:
    """Phân tích HTTP response để tìm lỗ hổng bảo mật.
    
    Args:
        record: Dict chứa status, headers, body từ HTTP response
        
    Returns:
        Danh sách findings, mỗi item là dict với rule_id, severity, evidence
    """
    ...
```

#### JavaScript/CSS:
- Sử dụng const/let, không dùng var
- Semicolons bắt buộc
- Indent: 2 spaces

### 6. Testing Requirements

#### Mỗi PR phải có:
- Unit tests cho logic mới (nếu thêm tính năng)
- Regression tests (nếu sửa lỗi)
- Cập nhật test fixtures nếu thay đổi schema

#### Chạy tests:
```bash
# Toàn bộ test suite
python -m pytest tests/ -v

# Chỉ test cụ thể
python -m pytest tests/test_core.py::test_target_address -v

# Với coverage
python -m pytest tests/ --cov=juicesec --cov-report=term-missing
```

### 7. Bảo Mật

#### ⚠️ NGHIÊM CẤM:
- Commit secrets, API keys, passwords
- Hardcode credentials trong code
- Expose sensitive data trong logs
- Sử dụng dependencies có CVE nghiêm trọng chưa vá

#### Checklist bảo mật:
- [ ] Không có secret nào được commit
- [ ] Input validation đầy đủ
- [ ] Error messages không lộ thông tin nhạy cảm
- [ ] Dependencies đã quét qua `pip-audit` (nếu thêm mới)

### 8. Documentation

Khi thay đổi API hoặc behavior:
- Cập nhật [`README.md`](README.md)
- Cập nhật docstrings
- Thêm ví dụ sử dụng nếu cần
- Ghi vào [`CHANGELOG.md`](CHANGELOG.md)

### 9. Review Process

PR cần:
- ✅ Tất cả CI checks pass
- ✅ Ít nhất 1 approval từ maintainer
- ✅ Không có unresolved comments
- ✅ Branch cập nhật với `main`

### 10. Code of Conduct

- Tôn trọng tất cả contributors
- Constructive feedback
- Tập trung vào code, không công kích cá nhân
- Giữ discussions chuyên nghiệp và lịch sự

## Liên Hệ

Nếu có câu hỏi, tạo issue hoặc discussion trên GitHub.

---

Cảm ơn bạn đã đóng góp! 🎉
