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


def parse_openapi_spec(spec_body: str) -> dict:
    """Extract endpoints and parameters from OpenAPI/Swagger spec (v2 or v3).
    
    Returns dict: {"/path": {"methods": ["GET", "POST"], "params": [{"name": "id", "type": "integer", "in": "query"}]}}
    Uses only stdlib json - no external parsers.
    """
    try:
        spec = json.loads(spec_body)
    except (json.JSONDecodeError, ValueError):
        return {}
    
    endpoints = {}
    
    # OpenAPI v3 uses "openapi" field, Swagger v2 uses "swagger"
    is_v3 = "openapi" in spec
    paths_obj = spec.get("paths", {})
    
    for path, path_item in paths_obj.items():
        if not isinstance(path_item, dict):
            continue
        
        methods = []
        params = []
        
        for method in ["get", "post", "put", "delete", "patch", "head", "options"]:
            if method in path_item:
                methods.append(method.upper())
                operation = path_item[method]
                
                # Extract parameters (query, path, header)
                operation_params = operation.get("parameters", [])
                if isinstance(operation_params, list):
                    for param in operation_params:
                        if not isinstance(param, dict):
                            continue
                        
                        param_info = {
                            "name": param.get("name", ""),
                            "in": param.get("in", "query"),
                            "required": param.get("required", False)
                        }
                        
                        # Extract type (v2 vs v3 differ)
                        if is_v3:
                            schema = param.get("schema", {})
                            param_info["type"] = schema.get("type", "string")
                            param_info["format"] = schema.get("format")
                        else:
                            param_info["type"] = param.get("type", "string")
                            param_info["format"] = param.get("format")
                        
                        params.append(param_info)
        
        if methods:
            endpoints[path] = {"methods": methods, "params": params}
    
    return endpoints


def generate_fuzz_payloads(param_type: str, param_format: str | None = None) -> list[str]:
    """Generate fuzzing payloads based on parameter type.
    
    Returns boundary values, type mismatches, and injection patterns.
    Conservative - does not attempt actual exploitation, only discovery.
    """
    payloads = []
    
    if param_type == "integer":
        # Boundary values
        payloads.extend(["0", "-1", "2147483647", "-2147483648", "99999999999"])
        # Type mismatches
        payloads.extend(["abc", "1.5", "null", "true"])
    
    elif param_type == "number":
        payloads.extend(["0", "-1", "0.0", "1.7976931348623157e+308", "-1.7976931348623157e+308"])
        payloads.extend(["abc", "null", "NaN", "Infinity"])
    
    elif param_type == "boolean":
        payloads.extend(["true", "false", "1", "0", "yes", "no"])
        payloads.extend(["abc", "null"])
    
    elif param_type == "array":
        payloads.extend(["[]", "[1,2,3]", '["a","b"]', "null"])
        payloads.extend(["abc", "1"])
    
    else:  # string (default)
        # Basic boundary
        payloads.append("")
        payloads.append("a" * 1000)
        
        # SQL injection patterns (discovery, not exploitation)
        payloads.extend(["'", "''", "1' OR '1'='1", "admin'--"])
        
        # XSS patterns (discovery)
        payloads.extend(["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"])
        
        # Path traversal patterns
        payloads.extend(["../", "..\\", "....//", "/etc/passwd"])
        
        # Command injection patterns
        payloads.extend(["; ls", "| whoami", "`id`", "$(cat /etc/passwd)"])
        
        # NoSQL injection patterns
        payloads.extend(['{"$ne": null}', '{"$gt": ""}'])
        
        # LDAP injection patterns
        payloads.extend(["*", "*()|&", "admin*"])
    
    return payloads


def discover_endpoints_from_openapi(url: str, timeout: float = 3.0) -> list[str]:
    """Fetch /api-docs/ and extract dynamic endpoints for fuzzing.
    
    Returns list of paths to test beyond the static PATHS list.
    Falls back to empty list if /api-docs/ is unavailable or malformed.
    """
    discovered = []
    
    try:
        host, port = target_address(url)
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        try:
            conn.request("GET", "/api-docs/", headers={"User-Agent": "JuiceSec-Education/1.0",
                                                        "Accept": "application/json"})
            response = conn.getresponse()
            
            if response.status == 200:
                raw = response.read(MAX_BODY + 1)[:MAX_BODY]
                spec_body = raw.decode("utf-8", errors="replace")
                
                endpoints = parse_openapi_spec(spec_body)
                
                # Generate test paths from discovered endpoints
                for path, info in endpoints.items():
                    # Add base path
                    discovered.append(path)
                    
                    # For each parameter, generate fuzzing variants
                    query_params = [p for p in info.get("params", []) if p["in"] == "query"]
                    
                    if query_params:
                        for param in query_params[:3]:  # Limit to first 3 params to avoid explosion
                            param_type = param.get("type", "string")
                            param_format = param.get("format")
                            param_name = param["name"]
                            
                            # Generate 2-3 representative payloads per parameter
                            payloads = generate_fuzz_payloads(param_type, param_format)[:3]
                            
                            for payload in payloads:
                                # URL encode the payload
                                from urllib.parse import quote
                                encoded = quote(payload, safe='')
                                test_path = f"{path}?{param_name}={encoded}"
                                discovered.append(test_path)
        finally:
            conn.close()
    
    except (OSError, http.client.HTTPException, ValueError, json.JSONDecodeError):
        # If OpenAPI discovery fails, return empty list - fall back to static PATHS
        pass
    
    # Deduplicate and limit to prevent DoS against target
    seen = set()
    unique = []
    for path in discovered:
        if path not in seen and len(unique) < 50:  # Cap at 50 discovered paths
            seen.add(path)
            unique.append(path)
    
    return unique


def target_address(url):
    """Parse and pin localhost to an IP, so DNS cannot change the destination."""
    if not isinstance(url, str) or any(c.isspace() for c in url):
        raise ValueError("URL must be a string without whitespace")
    try:
        u = urlsplit(url)
    except Exception as exc:
        raise ValueError(f"Malformed URL: {exc}") from exc
    if u.scheme != "http":
        raise ValueError("Only http scheme is allowed")
    if "@" in u.netloc or u.username or u.password:
        raise ValueError("Userinfo / credentials in URL are forbidden")
    if u.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("Only http://127.0.0.1, localhost or [::1] is allowed")
    if u.query or u.fragment or u.path not in ("", "/"):
        raise ValueError("Use an origin only; path, query and fragment are forbidden")
    try:
        port = 80 if u.port is None else u.port
    except ValueError as exc:
        raise ValueError("Invalid port") from exc
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("Invalid port")
    return ("::1" if u.hostname == "::1" else "127.0.0.1"), port


def collect(url, path, timeout=3.0, discovered_paths=None):
    """Collect HTTP response from target.
    
    Args:
        url: Target origin (http://127.0.0.1:port)
        path: Path to request
        timeout: Connection timeout
        discovered_paths: Optional list of dynamically discovered paths from OpenAPI
    """
    host, port = target_address(url)
    
    # Allow static PATHS, active probe path, and dynamically discovered paths
    allowed = PATHS + ["/rest/products/search?q=%27"]
    if discovered_paths:
        allowed.extend(discovered_paths)
    
    if path not in allowed:
        raise ValueError("Path not in the fixed lab profile or discovered endpoints")
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
            if key in ("set-cookie", "authorization", "proxy-authorization", "cookie"):
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
    ("SAST-DOM", "Gán vào HTML sink", r"(?:\.innerHTML\s*=\s*[^'\"\s]|\b(?:innerHTML|outerHTML)\s*=\s*[^'\"\s]|document\.write\s*\()", "CWE-79", "Dùng textContent khi hiển thị văn bản; phân tích nguồn dữ liệu."),
    ("SAST-EVAL", "Thực thi chuỗi như mã", r"\beval\s*\(", "CWE-95", "Thay eval bằng bộ phân tích dữ liệu có schema."),
    ("SAST-TRUST", "Bỏ qua kiểm tra HTML của framework", r"bypassSecurityTrust(?:Html|Script|Url|ResourceUrl)\s*\(", "CWE-79", "Xác minh luồng dữ liệu và loại bỏ việc tin cậy đầu vào người dùng."),
    ("SAST-JWT", "Có lời gọi decode token", r"(?:jwt|jsonwebtoken)\.decode\s*\(", "CWE-347", "Decode chỉ đọc dữ liệu; dùng verify trước quyết định quyền."),
    ("SAST-EXEC", "Có API chạy lệnh hệ điều hành", r"(?:child_process\.)?exec\s*\(", "CWE-78", "Dùng API nghiệp vụ; nếu cần process, cố định executable và tham số."),
    ("SAST-PATH", "Đọc tệp từ biến đầu vào", r"(?:readFile|sendFile)\s*\(\s*(?:req\.|request\.)", "CWE-22", "Ánh xạ ID sang tệp cố định; kiểm tra đường dẫn thực sau resolve."),
    ("SAST-SSRF", "Gửi HTTP từ biến request", r"(?:fetch|axios\.get|requests\.get)\s*\(\s*(?:req\.|request\.)", "CWE-918", "Giới hạn đích và kiểm tra redirect cùng địa chỉ kết nối thực."),
    ("SAST-XML", "Cho phép thực thể XML", r"(?:resolve_entities|load_dtd|noent)\s*[:=]\s*(?:True|true)", "CWE-611", "Tắt DTD và external entity ở parser."),
    ("SAST-DESER", "Giải tuần tự hóa đối tượng", r"\b(?:pickle\.loads|unserialize)\s*\(", "CWE-502", "Dùng dữ liệu JSON có schema thay vì khôi phục đối tượng không tin cậy.")
]


def _is_comment_line(line):
    """True when a line is only a comment, so regex hits on it are inert.

    The AST engine already strips comments before matching; the line-regex rules
    do not, which is the documented source of false positives such as
    ``// example only: node.innerHTML = user;``.
    """
    stripped = line.lstrip()
    return stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("#")


def _regex_findings(source, filename):
    out = []
    for number, line in enumerate(source.splitlines(), 1):
        # Skip comment-only lines to avoid the documented inert-code false positives.
        if _is_comment_line(line):
            continue
        for rule, title, pattern, cwe, fix in SAST_RULES:
            if re.search(pattern, line, re.I):
                f = finding(rule, title, "medium", "low",
                            {"file": str(filename)[:100], "line": number,
                             "snippet": line[:200]}, fix, cwe)
                f["engine"] = "line_regex"
                out.append(f)
                if len(out) >= 200:
                    return out
    return out


def analyze_source(source, filename="snippet.txt"):
    """Union of the line-regex rules and the AST/taint engine.

    The regex pass still covers patterns the flow engine does not model (JWT
    decode, framework trust bypass, access-control and CSRF route shapes). The
    AST pass adds cross-line data flow and drops comment-only false positives.

    A small context filter upgrades precision further: regex signals that the
    flow engine can prove inert are suppressed. For example a ``jwt.decode``
    used only for a debug preview is not an authorization decision, so the
    AST engine does not report it and the regex finding is dropped too.
    Findings from both engines are returned; duplicates are removed by
    (rule_id, line).
    """
    if not isinstance(source, str) or len(source.encode("utf-8")) > MAX_SOURCE:
        raise ValueError("Source exceeds 200000 UTF-8 bytes")
    from juicesec.astscan import analyze_ast, is_benign_token_decode
    regex_hits = [f for f in _regex_findings(source, filename)
                  if not (f["rule_id"] == "SAST-JWT" and is_benign_token_decode(source))]
    combined = regex_hits + analyze_ast(source, filename)
    seen, unique = set(), []
    for item in combined:
        key = (item["rule_id"], item["evidence"].get("line"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique[:200]




SCRIPT_TAG_RE = re.compile(
    r'<script\b([^>]*)>(.*?)</script>|<script\b([^>]*)/?>',
    re.DOTALL | re.IGNORECASE
)
SRC_ATTR_RE = re.compile(
    r'\bsrc\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))',
    re.IGNORECASE
)


def extract_client_scripts(html_text: str, base_url: str = "") -> list[tuple[str, str]]:
    """Extract scripts from HTML.
    Returns list of ('external', script_path) or ('inline', script_code).
    """
    if not html_text:
        return []
    scripts = []
    seen = set()
    for match in SCRIPT_TAG_RE.finditer(html_text):
        attrs = match.group(1) if match.group(1) is not None else (match.group(3) or "")
        body = match.group(2) or ""
        src_match = SRC_ATTR_RE.search(attrs)
        if src_match:
            raw_src = src_match.group(1) or src_match.group(2) or src_match.group(3) or ""
            raw_src = raw_src.strip()
            if raw_src:
                clean_src = raw_src.split("?")[0].split("#")[0].strip()
                if clean_src.startswith("//"):
                    continue
                elif clean_src.startswith("http://") or clean_src.startswith("https://"):
                    if base_url:
                        from urllib.parse import urlparse
                        p_src = urlparse(clean_src)
                        p_base = urlparse(base_url)
                        if p_src.netloc != p_base.netloc:
                            continue
                        full_path = p_src.path
                    else:
                        continue
                elif clean_src.startswith("/"):
                    full_path = clean_src
                else:
                    full_path = "/" + clean_src

                entry = ("external", full_path)
                if entry not in seen:
                    seen.add(entry)
                    scripts.append(entry)
                continue
        code = body.strip()
        if code:
            entry = ("inline", code)
            if entry not in seen:
                seen.add(entry)
                scripts.append(entry)
    return scripts


def scan(url, active=False, openapi_discovery=False, analyze_client=True):
    """Scan target with static and optionally dynamic endpoint discovery.
    
    Args:
        url: Target origin (http://127.0.0.1:port)
        active: Include active error probe (SQL injection test)
        openapi_discovery: Fetch /api-docs/ and fuzz discovered endpoints
        analyze_client: Extract and analyze client-side JavaScript for SAST + AI
    """
    target_address(url)
    records, findings, errors = [], [], []
    client_scripts_found = []
    client_source_sample = []
    
    # Start with static paths
    paths = list(PATHS)
    
    # Add active probe path
    if active:
        paths.append("/rest/products/search?q=%27")
    
    # Discover endpoints from OpenAPI if requested
    discovered = []
    if openapi_discovery:
        discovered = discover_endpoints_from_openapi(url)
        paths.extend(discovered)
    
    start = time.perf_counter()
    html_root_body = ""
    for path in paths:
        try:
            record = collect(url, path, discovered_paths=discovered)
            findings.extend(dict(f, path=path) for f in analyze_response(record))
            if path == "/" and "text/html" in record.get("headers", {}).get("content-type", "").lower():
                html_root_body = record.get("body", "")
            # Do not retain arbitrary target response content or cookies.
            records.append({k: v for k, v in record.items() if k not in ("body", "headers")})
        except (OSError, http.client.HTTPException, ValueError) as exc:
            errors.append({"path": path, "type": type(exc).__name__, "message": str(exc)[:160]})
    
    # Analyze client scripts from HTML if requested
    if analyze_client and html_root_body:
        extracted = extract_client_scripts(html_root_body, url)
        script_paths = []
        for stype, sdata in extracted:
            if stype == "external":
                client_scripts_found.append(sdata)
                if sdata.startswith("/") and sdata not in script_paths and len(script_paths) < 3:
                    script_paths.append(sdata)
            elif stype == "inline":
                inline_name = f"inline_script_{len(client_scripts_found) + 1}.js"
                client_scripts_found.append(inline_name)
                client_source_sample.append(sdata[:40000])
                try:
                    sast_hits = analyze_source(sdata[:MAX_SOURCE], inline_name)
                    findings.extend(dict(f, path="/" + inline_name) for f in sast_hits)
                except Exception:
                    pass
        
        # Sort script_paths to prioritize main, app, runtime, vendor
        def _script_prio(p):
            p_low = p.lower()
            for idx, kw in enumerate(["main", "app", "runtime", "vendor", "bundle"]):
                if kw in p_low:
                    return idx
            return 10
        script_paths.sort(key=_script_prio)

        # Collect external scripts
        for s_path in script_paths[:2]:
            try:
                s_rec = collect(url, s_path, discovered_paths=script_paths)
                s_body = s_rec.get("body", "")
                if s_body:
                    client_source_sample.append(s_body[:40000])
                    sast_hits = analyze_source(s_body[:MAX_SOURCE], s_path.lstrip("/"))
                    findings.extend(dict(f, path=s_path) for f in sast_hits)
            except Exception as exc:
                errors.append({"path": s_path, "type": type(exc).__name__, "message": str(exc)[:160]})

    mode = "openapi_fuzz" if openapi_discovery else ("active_error_probe" if active else "baseline")
    metadata = {}
    if openapi_discovery:
        metadata["discovered_endpoints"] = len(discovered)
    if analyze_client:
        metadata["client_scripts_found"] = len(client_scripts_found)

    combined_client_code = "\n\n".join(client_source_sample)
    return {"schema_version": "1.2", "mode": mode,
            "target": url, "generated_at": datetime.now(timezone.utc).isoformat(),
            "duration_ms": round((time.perf_counter()-start)*1000, 3),
            "findings": findings, "records": records, "errors": errors,
            "client_source_sample": combined_client_code,
            **metadata,
            "limits": ["Heuristics, not exploit confirmation", "No browser execution",
                       "No authenticated access-control testing", "No CVSS auto-scoring"]}


def html_report(report):
    """All imported report values remain escaped, including code and payloads."""
    esc = lambda value: html.escape(str(value), quote=True)
    rows = []
    for f in report.get("findings", []):
        rows.append("<tr>"+"".join("<td>"+esc(f.get(k, ""))+"</td>" for k in
                    ("rule_id", "title", "severity", "confidence", "status", "evidence", "remediation"))+"</tr>")
    gauge_html = ""
    gauge = report.get("ai_gauge")
    if gauge and isinstance(gauge, dict):
        risk = gauge.get("risk_percent", 0)
        findings_num = gauge.get("findings", 0)
        total_num = gauge.get("total", 0)
        badge_color = "#d93025" if risk >= 70 else ("#f29900" if risk >= 40 else "#0f8b7d")
        badge_label = "Cao" if risk >= 70 else ("Trung bình" if risk >= 40 else "Thấp")
        gauge_html = (
            f"<div style='border:1px solid #cbd5e1;border-radius:12px;padding:16px 20px;margin:20px 0;background:#f8fafc;"
            f"display:flex;align-items:center;gap:24px;box-shadow:0 1px 3px rgba(0,0,0,0.05);'>"
            f"<div style='width:90px;height:90px;min-width:90px;border-radius:50%;border:7px solid {badge_color};"
            f"display:flex;align-items:center;justify-content:center;font-size:22px;font-weight:700;color:{badge_color};'>{risk}%</div>"
            f"<div><h3 style='margin:0 0 6px 0;font-size:18px;'>AI Risk Gauge (Hybrid Bayesian)</h3>"
            f"<p style='margin:4px 0;'>Mức độ rủi ro: <strong style='color:{badge_color};'>{badge_label}</strong></p>"
            f"<p style='margin:4px 0;'>Điểm nghi ngờ / Tổng kiểm tra: <strong>{findings_num} / {total_num}</strong></p></div></div>"
        )
    return ("<!doctype html><html lang='vi'><meta charset='utf-8'>"
            "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'\">"
            "<title>JuiceSec report</title><style>body{font:16px system-ui;margin:40px;line-height:1.5}"
            "table{border-collapse:collapse;width:100%}td,th{border:1px solid #bbb;padding:8px;text-align:left;overflow-wrap:anywhere}"
            "pre{white-space:pre-wrap;overflow-wrap:anywhere}</style><h1>Báo cáo JuiceSec Analyzer</h1>"
            "<p>Cảnh báo cần thẩm định; dữ liệu này không tự xác nhận khai thác.</p><p>Đích: "+esc(report.get("target", "source review"))+"</p>"
            + gauge_html +
            "<table><tr><th>Quy tắc</th><th>Tiêu đề</th><th>Mức độ</th><th>Tin cậy</th><th>Trạng thái</th><th>Bằng chứng</th><th>Khắc phục</th></tr>"
            +"".join(rows)+"</table><h2>Dữ liệu và giới hạn</h2><pre>"+esc(json.dumps(report, ensure_ascii=False, indent=2))+"</pre></html>")
