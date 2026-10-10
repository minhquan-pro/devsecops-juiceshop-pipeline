"""Bounded HTTP collection and conservative rule-based analysis.

Only loopback HTTP is supported. There is no crawler, redirect following,
credential guessing, token forgery, or automatic exploitation.
"""
from __future__ import annotations

import hashlib
import html
import http.client
import json
import re
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

MAX_BODY = 262144
MAX_SOURCE = 200000
PATHS = ["/", "/rest/products/search?q=juice", "/api-docs/", "/metrics", "/ftp/"]


def target_address(url):
    """Parse and pin localhost to an IP, so DNS cannot change the destination."""
    if not isinstance(url, str) or any(c.isspace() for c in url):
        raise ValueError("URL must be a string without whitespace")
    u = urlsplit(url)
    if u.scheme != "http" or u.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("Only http://127.0.0.1, localhost or [::1] is allowed")
    if u.username or u.password or u.query or u.fragment or u.path not in ("", "/"):
        raise ValueError("Use an origin only; credentials, path, query and fragment are forbidden")
    port = 80 if u.port is None else u.port
    if not 1 <= port <= 65535:
        raise ValueError("Invalid port")
    return ("::1" if u.hostname == "::1" else "127.0.0.1"), port


def collect(url, path, timeout=3.0):
    host, port = target_address(url)
    if path not in PATHS + ["/rest/products/search?q=%27"]:
        raise ValueError("Path not in the fixed lab profile")
    start = time.perf_counter()
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", path, headers={"User-Agent": "JuiceSec-Education/1.0",
                                          "Accept-Encoding": "identity"})
        response = conn.getresponse()
        raw = response.read(MAX_BODY + 1)
        truncated = len(raw) > MAX_BODY
        raw = raw[:MAX_BODY]
        headers = {}
        for k, v in response.getheaders():
            key = k.lower()
            # Credentials must not enter evidence or reports.
            if key in ("set-cookie", "authorization", "proxy-authorization"):
                headers[key] = "[REDACTED]"
            else:
                headers[key] = v[:4096]
        return {"path": path, "status": response.status, "headers": headers,
                "body": raw.decode("utf-8", errors="replace"), "truncated": truncated,
                "sha256_prefix": hashlib.sha256(raw).hexdigest(),
                "bytes_captured": len(raw), "elapsed_ms": round((time.perf_counter()-start)*1000, 3)}
    finally:
        conn.close()


def finding(rule, title, severity, confidence, evidence, remediation, cwe):
    return {"rule_id": rule, "title": title, "severity": severity,
            "confidence": confidence, "status": "needs_review", "cwe": cwe,
            "evidence": evidence, "remediation": remediation}


def analyze_response(record):
    """Indicators are not labelled confirmed vulnerabilities."""
    out = []
    status = record.get("status", 0)
    if not isinstance(status, int) or not 200 <= status < 600:
        return out
    path = record.get("path", "")
    body = record.get("body", "")
    headers = {k.lower(): str(v) for k, v in record.get("headers", {}).items()}
    content_type = headers.get("content-type", "").lower()
    if path == "/" and 200 <= status < 300 and "text/html" in content_type:
        required = {"content-security-policy": "Content Security Policy",
                    "x-content-type-options": "X Content Type Options"}
        for key, title in required.items():
            if not headers.get(key, "").strip():
                out.append(finding("HDR-"+key, "Thiếu "+title, "low", "high",
                                   "Không thấy header trên HTML gốc; không suy ra XSS.",
                                   "Đánh giá chính sách theo ngữ cảnh và kiểm thử hồi quy.", "CWE-693"))
        csp = headers.get("content-security-policy", "").lower()
        if not headers.get("x-frame-options", "").strip() and "frame-ancestors" not in csp:
            out.append(finding("HDR-FRAME", "Chưa thấy chính sách chống nhúng khung", "low", "medium",
                               "Không có X-Frame-Options hoặc chỉ thị CSP frame-ancestors.",
                               "Đặt frame-ancestors phù hợp ở phản hồi HTML.", "CWE-1021"))
    if path == "/metrics" and status == 200 and "text" in content_type:
        if re.search(r"^# (?:HELP|TYPE)\s+\w+", body, re.M) and re.search(r"^[a-zA-Z_:][\w:]*\s*(?:\{[^\n]*\})?\s+[-+\d]", body, re.M):
            out.append(finding("INFO-METRICS", "Endpoint xuất dữ liệu đo lường", "low", "high",
                               "Nội dung có cấu trúc Prometheus; cần kiểm tra dữ liệu và quyền truy cập.",
                               "Tách mạng quản trị hoặc kiểm soát quyền đọc metrics.", "CWE-200"))
    if path == "/api-docs/" and status == 200:
        if re.search(r"swagger-ui|\"openapi\"\s*:|\"swagger\"\s*:", body, re.I):
            out.append(finding("INFO-API", "Phát hiện tài liệu API", "info", "medium",
                               "Tài liệu API có thể được công bố có chủ đích; chưa đủ kết luận lộ dữ liệu.",
                               "Kiểm tra chính sách công bố và loại bỏ ví dụ chứa bí mật.", "CWE-200"))
    if path == "/ftp/" and status == 200:
        if re.search(r"Index of /ftp|<title>[^<]*[Dd]irectory|<a[^>]+href=[\"'][^\"']+\.(?:md|bak|pdf|zip)", body):
            out.append(finding("INFO-DIR", "Dấu hiệu danh sách tệp được công bố", "medium", "medium",
                               "Trang có chỉ mục hoặc liên kết tệp; chưa chứng minh path traversal.",
                               "Tách tệp công khai và riêng tư; kiểm tra quyền ở máy chủ.", "CWE-548"))
    if re.search(r"SQLITE_ERROR|SequelizeDatabaseError|Traceback \(most recent call last\)", body):
        out.append(finding("INFO-ERROR", "Thông báo lỗi nội bộ trong phản hồi", "medium", "high",
                           "Có dấu hiệu lỗi trình điều khiển hoặc stack trace; chưa xác nhận SQL injection.",
                           "Giữ chi tiết trong log cục bộ và trả thông báo lỗi chung.", "CWE-209"))
    return out


SAST_RULES = [
    ("SAST-SQL", "Chuỗi SQL có ghép dữ liệu", r"(?:SELECT|UPDATE|DELETE|INSERT).*(?:\+|\$\{)", "CWE-89", "Tham số hóa giá trị và dùng allowlist cho định danh."),
    ("SAST-DOM", "Gán vào HTML sink", r"(?:\.innerHTML\s*=|document\.write\s*\()", "CWE-79", "Dùng textContent khi hiển thị văn bản; phân tích nguồn dữ liệu."),
    ("SAST-EVAL", "Thực thi chuỗi như mã", r"\beval\s*\(", "CWE-95", "Thay eval bằng bộ phân tích dữ liệu có schema."),
    ("SAST-TRUST", "Bỏ qua kiểm tra HTML của framework", r"bypassSecurityTrust(?:Html|Script|Url|ResourceUrl)\s*\(", "CWE-79", "Xác minh luồng dữ liệu và loại bỏ việc tin cậy đầu vào người dùng."),
    ("SAST-JWT", "Có lời gọi decode token", r"(?:jwt|jsonwebtoken)\.decode\s*\(", "CWE-347", "Decode chỉ đọc dữ liệu; dùng verify trước quyết định quyền."),
    ("SAST-EXEC", "Có API chạy lệnh hệ điều hành", r"(?:child_process\.)?exec\s*\(", "CWE-78", "Dùng API nghiệp vụ; nếu cần process, cố định executable và tham số."),
    ("SAST-PATH", "Đọc tệp từ biến đầu vào", r"(?:readFile|sendFile)\s*\(\s*(?:req\.|request\.)", "CWE-22", "Ánh xạ ID sang tệp cố định; kiểm tra đường dẫn thực sau resolve."),
    ("SAST-SSRF", "Gửi HTTP từ biến request", r"(?:fetch|axios\.get|requests\.get)\s*\(\s*(?:req\.|request\.)", "CWE-918", "Giới hạn đích và kiểm tra redirect cùng địa chỉ kết nối thực."),
    ("SAST-XML", "Cho phép thực thể XML", r"(?:resolve_entities|load_dtd|noent)\s*[:=]\s*(?:True|true)", "CWE-611", "Tắt DTD và external entity ở parser."),
    ("SAST-DESER", "Giải tuần tự hóa đối tượng", r"\b(?:pickle\.loads|unserialize)\s*\(", "CWE-502", "Dùng dữ liệu JSON có schema thay vì khôi phục đối tượng không tin cậy.")
]


def analyze_source(source, filename="snippet.txt"):
    if not isinstance(source, str) or len(source.encode("utf-8")) > MAX_SOURCE:
        raise ValueError("Source exceeds 200000 UTF-8 bytes")
    out = []
    for number, line in enumerate(source.splitlines(), 1):
        for rule, title, pattern, cwe, fix in SAST_RULES:
            if re.search(pattern, line, re.I):
                f = finding(rule, title, "medium", "low",
                            {"file": str(filename)[:100], "line": number,
                             "snippet": line[:200]}, fix, cwe)
                out.append(f)
                if len(out) >= 200:
                    return out
    return out


def scan(url, active=False):
    target_address(url)
    records, findings, errors = [], [], []
    paths = PATHS + (["/rest/products/search?q=%27"] if active else [])
    start = time.perf_counter()
    for path in paths:
        try:
            record = collect(url, path)
            findings.extend(dict(f, path=path) for f in analyze_response(record))
            # Do not retain arbitrary target response content or cookies.
            records.append({k: v for k, v in record.items() if k not in ("body", "headers")})
        except (OSError, http.client.HTTPException, ValueError) as exc:
            errors.append({"path": path, "type": type(exc).__name__, "message": str(exc)[:160]})
    return {"schema_version": "1.0", "mode": "active_error_probe" if active else "baseline",
            "target": url, "generated_at": datetime.now(timezone.utc).isoformat(),
            "duration_ms": round((time.perf_counter()-start)*1000, 3),
            "findings": findings, "records": records, "errors": errors,
            "limits": ["Heuristics, not exploit confirmation", "No browser execution",
                       "No authenticated access-control testing", "No CVSS auto-scoring"]}


def html_report(report):
    """All imported report values remain escaped, including code and payloads."""
    esc = lambda value: html.escape(str(value), quote=True)
    rows = []
    for f in report.get("findings", []):
        rows.append("<tr>"+"".join("<td>"+esc(f.get(k, ""))+"</td>" for k in
                    ("rule_id", "title", "severity", "confidence", "status", "evidence", "remediation"))+"</tr>")
    return ("<!doctype html><html lang='vi'><meta charset='utf-8'>"
            "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'\">"
            "<title>JuiceSec report</title><style>body{font:16px system-ui;margin:40px;line-height:1.5}"
            "table{border-collapse:collapse;width:100%}td,th{border:1px solid #bbb;padding:8px;text-align:left;overflow-wrap:anywhere}"
            "pre{white-space:pre-wrap;overflow-wrap:anywhere}</style><h1>Báo cáo JuiceSec Analyzer</h1>"
            "<p>Cảnh báo cần thẩm định; dữ liệu này không tự xác nhận khai thác.</p><p>Đích: "+esc(report.get("target", "source review"))+"</p>"
            "<table><tr><th>Quy tắc</th><th>Tiêu đề</th><th>Mức độ</th><th>Tin cậy</th><th>Trạng thái</th><th>Bằng chứng</th><th>Khắc phục</th></tr>"
            +"".join(rows)+"</table><h2>Dữ liệu và giới hạn</h2><pre>"+esc(json.dumps(report, ensure_ascii=False, indent=2))+"</pre></html>")
