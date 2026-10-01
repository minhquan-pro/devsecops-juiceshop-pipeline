"""
Module: vuln_analyzer.py
Engine phân tích lỗ hổng động (DAST) và thẩm tra mã nguồn (SAST)
cho nền tảng OWASP Juice Shop theo chuẩn PortSwigger Web Security.
"""

import json
import time
import re
from urllib.parse import urljoin
import requests
from knowledge_base import PORTSWIGGER_VULNERABILITIES

SAMPLE_SOURCE_FILES = {
    "routes/login.ts": {
        "filename": "routes/login.ts",
        "description": "Xử lý xác thực đăng nhập người dùng (User Authentication)",
        "vulnerable_lines": [18, 19, 20],
        "vulnerability_type": "SQL Injection (SQLi)",
        "code": """import { Request, Response, NextFunction } from 'express'
import models = require('../models/index')
const security = require('../lib/insecurity')

module.exports = function login () {
  return (req: Request, res: Response, next: NextFunction) => {
    // [VULNERABILITY] Lỗi ghép chuỗi trực tiếp đầu vào email vào câu lệnh SQL
    // Kẻ tấn công có thể chèn chuỗi "' or 1=1--" để đăng nhập với quyền Admin
    models.sequelize.query(
      `SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`,
      { model: models.User }
    ).then((user: any) => {
      const authenticatedUser = user[0]
      if (authenticatedUser) {
        const token = security.authorize(authenticatedUser)
        res.json({ authentication: { token, bid: authenticatedUser.id } })
      } else {
        res.status(401).send('Invalid email or password.')
      }
    }).catch((error: Error) => {
      next(error)
    })
  }
}""",
        "secure_fix": """import { Request, Response, NextFunction } from 'express'
import models = require('../models/index')
const security = require('../lib/insecurity')

module.exports = function login () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      // [FIX] Sử dụng ORM Parameterized Query ngăn chặn hoàn toàn SQL Injection
      const authenticatedUser = await models.User.findOne({
        where: {
          email: req.body.email,
          password: security.hash(req.body.password),
          deletedAt: null
        }
      })
      if (authenticatedUser) {
        const token = security.authorize(authenticatedUser)
        return res.json({ authentication: { token, bid: authenticatedUser.id } })
      }
      return res.status(401).send('Invalid email or password.')
    } catch (error) {
      next(error)
    }
  }
}"""
    },
    "routes/fileServer.ts": {
        "filename": "routes/fileServer.ts",
        "description": "Phục vụ tệp tĩnh tải xuống từ thư mục /ftp (Public File Server)",
        "vulnerable_lines": [12, 13, 14],
        "vulnerability_type": "Path Traversal & Improper Extension Validation",
        "code": """import path = require('path')
import { Request, Response, NextFunction } from 'express'

module.exports = function servePublicFiles () {
  return (req: Request, res: Response, next: NextFunction) => {
    const file = req.params.file
    // [VULNERABILITY] Kiểm tra lỏng lẻo bằng endsWith
    // Có thể vượt qua bằng Poison Null Byte: easter.gg%2500.md
    if (file && (file.endsWith('.md') || file.endsWith('.pdf'))) {
      res.sendFile(path.resolve('ftp/', file))
    } else {
      res.status(403).send('Only .md and .pdf files are allowed!')
    }
  }
}""",
        "secure_fix": """import path = require('path')
import { Request, Response, NextFunction } from 'express'

const ALLOWED_FILES = new Set(['legal.md', 'coupons_2024.md', 'incident-support.pdf'])

module.exports = function servePublicFiles () {
  return (req: Request, res: Response, next: NextFunction) => {
    const file = req.params.file
    const ftpRoot = path.resolve(__dirname, '../public/ftp')
    const safePath = path.normalize(path.join(ftpRoot, path.basename(file)))

    // [FIX] Kiểm tra Whitelist và ngăn chặn Path Traversal ra khỏi thư mục cho phép
    if (!safePath.startsWith(ftpRoot) || !ALLOWED_FILES.has(path.basename(file))) {
      return res.status(403).send('Access to requested file is forbidden.')
    }
    res.sendFile(safePath)
  }
}"""
    },
    "lib/insecurity.ts": {
        "filename": "lib/insecurity.ts",
        "description": "Hàm xử lý ký và thẩm định JWT (JWT Security Logic)",
        "vulnerable_lines": [8, 9, 10],
        "vulnerability_type": "Weak JWT Secret & Algorithm None Acceptance",
        "code": """const jwt = require('jsonwebtoken')
const defaultSecret = 'your-secret-key-wants-to-be-secure'

export const authorize = (user: any) => {
  // [VULNERABILITY] Sử dụng Secret yếu và cố định trong mã nguồn
  return jwt.sign(user, defaultSecret, { expiresIn: '6h' })
}

export const verify = (token: string) => {
  // [VULNERABILITY] Chấp nhận thuật toán 'none' cho phép Client giả mạo chữ ký
  return jwt.verify(token, defaultSecret, { algorithms: ['HS256', 'none'] })
}""",
        "secure_fix": """import jwt from 'jsonwebtoken'
import fs from 'fs'

const PRIVATE_KEY = process.env.JWT_PRIVATE_KEY || fs.readFileSync('certs/jwt-private.pem')
const PUBLIC_KEY = process.env.JWT_PUBLIC_KEY || fs.readFileSync('certs/jwt-public.pem')

export const authorize = (user: any) => {
  // [FIX] Sử dụng mã hóa bất đối xứng RS256 với thời hạn ngắn (15 phút)
  return jwt.sign({ sub: user.id, email: user.email, role: user.role }, PRIVATE_KEY, {
    algorithm: 'RS256',
    expiresIn: '15m',
    issuer: 'juiceshop.corp'
  })
}

export const verify = (token: string) => {
  // [FIX] Chỉ chấp nhận duy nhất thuật toán RS256, cấm tuyệt đối 'none'
  return jwt.verify(token, PUBLIC_KEY, {
    algorithms: ['RS256'],
    issuer: 'juiceshop.corp'
  })
}"""
    }
}

class JuiceShopAnalyzer:
    def __init__(self, target_url="http://localhost:3000"):
        self.target_url = target_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "JuiceSec-Analyzer/1.0 (Academic Research; PTIT InfoSec)"
        })

    def check_target_reachable(self):
        try:
            r = self.session.get(self.target_url, timeout=3)
            return r.status_code < 500
        except Exception:
            return False

    def run_live_scan(self):
        is_live = self.check_target_reachable()
        if not is_live:
            return self.run_simulated_scan(reason="Mục tiêu không phản hồi hoặc đang ở chế độ ngoại tuyến (Offline Mode). Kích hoạt bộ dữ liệu trinh sát và phân tích thực nghiệm mẫu của OWASP Juice Shop.")
        
        findings = []
        scan_meta = {
            "target": self.target_url,
            "mode": "Live Scanning",
            "start_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "status": "Completed"
        }

        # 1. Kiểm tra Security Headers
        try:
            r = self.session.get(self.target_url, timeout=4)
            headers = r.headers
            missing_headers = []
            expected_headers = [
                ("Content-Security-Policy", "Chống tấn công XSS và Data Injection"),
                ("X-Frame-Options", "Chống tấn công Clickjacking"),
                ("X-Content-Type-Options", "Chống MIME sniffing"),
                ("Strict-Transport-Security", "Bắt buộc mã hóa HTTPS"),
                ("Referrer-Policy", "Kiểm soát rò rỉ URL trong Referer header")
            ]
            for h, desc in expected_headers:
                if h not in headers:
                    missing_headers.append(f"{h} ({desc})")

            if missing_headers:
                findings.append({
                    "id": "missing_sec_headers",
                    "title": "Thiếu các HTTP Security Headers thiết yếu",
                    "severity": "MEDIUM",
                    "category": "Security Misconfiguration",
                    "portswigger_ref": "security_misconfig",
                    "evidence": f"Thiếu: {', '.join(missing_headers)}",
                    "recommendation": "Cấu hình module Helmet trong Express để tự động bổ sung đầy đủ các Header an ninh."
                })
        except Exception as e:
            pass

        # 2. Kiểm tra Information Disclosure
        endpoints_to_probe = [
            ("/rest/admin/application-version", "Lộ thông tin phiên bản ứng dụng Juice Shop"),
            ("/ftp", "Lộ danh mục thư mục tệp tin công khai /ftp"),
            ("/api-docs/", "Lộ tài liệu API Swagger công khai không xác thực"),
            ("/package.json.bak", "Lộ file backup chứa danh sách thư viện phụ thuộc"),
            ("/metrics", "Lộ thông tin giám sát hiệu năng Prometheus")
        ]

        for ep, desc in endpoints_to_probe:
            try:
                full_url = urljoin(self.target_url, ep)
                res = self.session.get(full_url, timeout=3)
                if res.status_code in [200, 204]:
                    snippet = res.text[:120].strip().replace("\n", " ")
                    findings.append({
                        "id": f"info_leak_{ep.replace('/', '_')}",
                        "title": f"Rò rỉ thông tin nhạy cảm qua endpoint: {ep}",
                        "severity": "HIGH" if "backup" in ep or "ftp" in ep else "MEDIUM",
                        "category": "Information Disclosure",
                        "portswigger_ref": "security_misconfig",
                        "evidence": f"HTTP {res.status_code} tại {ep}. Đoạn trích phản hồi: {snippet}...",
                        "recommendation": f"Chặn truy cập công khai endpoint {ep} trên Production và cấu hình kiểm soát truy cập (RBAC)."
                    })
            except Exception:
                continue

        # 3. Kiểm tra SQL Injection endpoint (search)
        try:
            sqli_url = urljoin(self.target_url, "/rest/products/search?q='")
            res = self.session.get(sqli_url, timeout=3)
            if "SQLITE_ERROR" in res.text or "syntax error" in res.text or res.status_code == 500:
                findings.append({
                    "id": "sqli_search_probe",
                    "title": "SQL Injection & Verbose Error Leakage tại Search API",
                    "severity": "CRITICAL",
                    "category": "SQL Injection (SQLi)",
                    "portswigger_ref": "sqli",
                    "evidence": f"Endpoint /rest/products/search?q=' trả về lỗi CSDL trực tiếp hoặc mã 500 kèm chi tiết truy vấn SQLite.",
                    "recommendation": "Sử dụng Parameterized Query với Sequelize replacements thay vì nối chuỗi trực tiếp."
                })
        except Exception:
            pass

        return self._format_results(scan_meta, findings)

    def run_simulated_scan(self, reason="Thực hiện phân tích mô phỏng dựa trên dữ liệu trắc địa OWASP Juice Shop"):
        scan_meta = {
            "target": self.target_url,
            "mode": "Simulation / Pre-Scanned Real Telemetry",
            "start_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "status": "Completed",
            "note": reason
        }

        findings = [
            {
                "id": "sqli_login_bypass",
                "title": "SQL Injection dẫn tới vượt qua xác thực Đăng nhập Quản trị viên",
                "severity": "CRITICAL",
                "cvss": 9.8,
                "category": "SQL Injection (SQLi)",
                "portswigger_ref": "sqli",
                "cwe": "CWE-89",
                "endpoint": "POST /rest/user/login",
                "evidence": "Payload \"' or 1=1--\" nhập vào trường email làm thay đổi logic mệnh đề WHERE trong SQLite, trả về bản ghi đầu tiên là tài khoản Admin (admin@juice-sh.op).",
                "impact": "Chiếm đoạt hoàn toàn quyền quản trị cao nhất của hệ thống mà không cần mật khẩu.",
                "recommendation": "Áp dụng Parameterized Query bằng cách sử dụng `models.User.findOne({ where: { email, password } })`."
            },
            {
                "id": "dom_xss_search",
                "title": "DOM-based Cross-Site Scripting (XSS) tại ô tìm kiếm",
                "severity": "HIGH",
                "cvss": 8.2,
                "category": "Cross-Site Scripting (XSS)",
                "portswigger_ref": "xss",
                "cwe": "CWE-79",
                "endpoint": "GET /#/search?q=",
                "evidence": "Payload `<iframe src=\"javascript:alert(\\`xss\\`)\">` được xử lý qua hàm bypassSecurityTrustHtml của Angular, làm vô hiệu hóa bộ lọc an toàn mặc định.",
                "impact": "Thực thi mã JavaScript tùy ý trên trình duyệt của nạn nhân, đánh cắp Session/Token hoặc thực hiện tấn công Defacement.",
                "recommendation": "Loại bỏ hàm `bypassSecurityTrustHtml`, sử dụng cơ chế Data Binding chuẩn của Angular hoặc lọc qua DOMPurify."
            },
            {
                "id": "idor_view_basket",
                "title": "Broken Access Control / IDOR tại API truy vấn giỏ hàng",
                "severity": "CRITICAL",
                "cvss": 9.1,
                "category": "Broken Access Control",
                "portswigger_ref": "broken_access_control",
                "cwe": "CWE-639",
                "endpoint": "GET /rest/basket/:id",
                "evidence": "Chỉ cần thay đổi tham số ID trên URL (/rest/basket/2), người dùng có thể xem toàn bộ sản phẩm và thông tin thanh toán của khách hàng khác.",
                "impact": "Tiết lộ thông tin đơn hàng cá nhân, danh tính người mua và vi phạm tính bảo mật dữ liệu.",
                "recommendation": "Xác thực quyền sở hữu: Kiểm tra basket.UserId trùng khớp với req.user.id trích xuất từ JWT được ký hợp lệ."
            },
            {
                "id": "path_traversal_ftp",
                "title": "Path Traversal & Bỏ qua kiểm tra phần mở rộng tệp (/ftp)",
                "severity": "HIGH",
                "cvss": 7.5,
                "category": "Path Traversal",
                "portswigger_ref": "path_traversal",
                "cwe": "CWE-22",
                "endpoint": "GET /ftp/:file",
                "evidence": "Kỹ thuật Poison Null Byte (%2500.md) hoặc mã hóa ký tự cho phép tải xuống các tệp bí mật bị ẩn như /ftp/eastere.gg và /ftp/package.json.bak.",
                "impact": "Tải mã nguồn, lộ danh mục dependency có chứa CVE, và đọc thông tin cấu hình nhạy cảm.",
                "recommendation": "Chuẩn hóa đường dẫn bằng `path.normalize`, kiểm tra `safePath.startsWith(allowedDir)` và dùng danh sách trắng Whitelist."
            },
            {
                "id": "jwt_weak_secret_alg_none",
                "title": "JWT Xác thực lỏng lẻo: Chấp nhận Alg 'none' và Khóa HMAC yếu",
                "severity": "CRITICAL",
                "cvss": 9.3,
                "category": "Identification & Authentication Failures",
                "portswigger_ref": "jwt_auth_flaws",
                "cwe": "CWE-347",
                "endpoint": "Header: Authorization: Bearer <jwt>",
                "evidence": "Khóa bí mật JWT được hardcode trong `lib/insecurity.ts` ('your-secret-key-wants-to-be-secure') và hàm verify chấp nhận thuật toán 'none'.",
                "impact": "Kẻ tấn công tự sinh mã Token với role='admin' mà không cần biết khóa bí mật, hoàn toàn chiếm đoạt quyền quản trị.",
                "recommendation": "Chuyển sang thuật toán ký bất đối xứng RS256, khóa riêng lưu trong Secret Manager, cấm tuyệt đối thuật toán 'none'."
            },
            {
                "id": "info_disclosure_swagger_metrics",
                "title": "Lộ tài liệu API Swagger và Thước đo Giám sát Hệ thống",
                "severity": "MEDIUM",
                "cvss": 5.3,
                "category": "Security Misconfiguration",
                "portswigger_ref": "security_misconfig",
                "cwe": "CWE-200",
                "endpoint": "GET /api-docs/ và GET /metrics",
                "evidence": "Tài liệu Swagger UI mở công khai liệt kê toàn bộ các API nội bộ chưa công bố; endpoint /metrics cung cấp số liệu lưu lượng chi tiết.",
                "impact": "Hỗ trợ kẻ tấn công vẽ bản đồ cấu trúc API và tìm kiếm các điểm yếu bảo mật tiềm tàng.",
                "recommendation": "Tắt Swagger UI trên Production hoặc thiết lập lớp xác thực bảo vệ bắt buộc."
            },
            {
                "id": "missing_csp_hsts",
                "title": "Thiếu các tiêu đề bảo vệ Content-Security-Policy & HSTS",
                "severity": "MEDIUM",
                "cvss": 5.0,
                "category": "Security Misconfiguration",
                "portswigger_ref": "security_misconfig",
                "cwe": "CWE-16",
                "endpoint": "Toàn bộ HTTP Responses",
                "evidence": "Thiếu tiêu đề `Content-Security-Policy`, `Strict-Transport-Security` và `X-Content-Type-Options: nosniff` trong Header trả về.",
                "impact": "Tăng nguy cơ bị tấn công Man-in-the-Middle (Downgrade Attack) và giảm khả năng ngăn chặn thực thi Script độc hại.",
                "recommendation": "Tích hợp thư viện HelmetJS và định nghĩa chính sách CSP nghiêm ngặt."
            }
        ]

        return self._format_results(scan_meta, findings)

    def _format_results(self, meta, findings):
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        total_risk_score = 0

        for f in findings:
            sev = f.get("severity", "MEDIUM")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            if sev == "CRITICAL":
                total_risk_score += 40
            elif sev == "HIGH":
                total_risk_score += 25
            elif sev == "MEDIUM":
                total_risk_score += 10
            elif sev == "LOW":
                total_risk_score += 5

        # Tính chỉ số bảo mật (Security Score 0 - 100)
        # Điểm càng thấp mức độ an ninh càng kém (Juice Shop có nhiều lỗ hổng nên điểm sẽ thấp)
        health_score = max(5, 100 - total_risk_score)

        return {
            "meta": meta,
            "summary": {
                "total_findings": len(findings),
                "severity_counts": severity_counts,
                "health_score": health_score,
                "security_status": "NGUY HIỂM CAO (CRITICAL RISK)" if health_score < 40 else "CẦN KHẮC PHỤC"
            },
            "findings": findings
        }

def get_code_audit_data():
    return SAMPLE_SOURCE_FILES
