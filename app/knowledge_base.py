"""
Knowledge Base: Phân tích chuyên sâu các nhóm lỗ hổng theo PortSwigger Web Security Academy
và Ánh xạ thực nghiệm tới các Thử thách (Challenges) trong OWASP Juice Shop.
Dành cho Đề tài Bài tập lớn An toàn Thông tin - PTIT.
"""

PORTSWIGGER_VULNERABILITIES = [
    {
        "id": "sqli",
        "name": "SQL Injection (SQLi)",
        "cwe": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
        "owasp_category": "A03:2021 - Injection",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "portswigger_summary": (
            "SQL Injection xảy ra khi kẻ tấn công can thiệp vào các truy vấn mà ứng dụng gửi đến cơ sở dữ liệu. "
            "PortSwigger phân loại SQLi thành ba nhóm chính: In-band (Union-based, Error-based), Inferential/Blind "
            "(Boolean-based, Time-based) và Out-of-band (OAST). Lỗ hổng cho phép xem trộm dữ liệu, vượt qua xác thực, "
            "sửa đổi cơ sở dữ liệu và thậm chí chiếm quyền điều khiển hệ điều hành máy chủ."
        ),
        "mechanism": (
            "Ứng dụng ghép trực tiếp chuỗi dữ liệu đầu vào do người dùng kiểm soát vào câu lệnh SQL thay vì sử dụng "
            "Prepared Statements (Tham số hóa). Dấu nháy đơn (') hoặc nháy kép (\") làm đóng chuỗi ký tự sớm, "
            "cho phép chèn thêm các toán tử logic (OR, AND) hoặc lệnh hợp nhất (UNION SELECT)."
        ),
        "detection_vectors": [
            "Kiểm tra ký tự đặc biệt: ' OR 1=1 --",
            "Kiểm tra Union-based: ' UNION SELECT null, null, username, password FROM Users--",
            "Kiểm tra Error-based: ' AND (SELECT 1/0) --",
            "Kiểm tra Time-based: '; WAITFOR DELAY '0:0:5'-- hoặc pg_sleep(5)"
        ],
        "juice_shop_challenges": [
            {
                "name": "Login Admin",
                "difficulty": 2,
                "category": "Injection",
                "endpoint": "POST /rest/user/login",
                "description": "Đăng nhập tài khoản quản trị viên tối cao (admin@juice-sh.op) mà không cần mật khẩu.",
                "attack_vector": "Payload: \"' or 1=1--\" nhập vào trường email khi gửi yêu cầu đăng nhập.",
                "root_cause_file": "routes/login.ts",
                "vulnerable_code": (
                    "// routes/login.ts (Juice Shop)\n"
                    "models.sequelize.query(\n"
                    "  `SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`,\n"
                    "  { model: models.User }\n"
                    ");"
                ),
                "remediated_code": (
                    "// Mã nguồn an toàn sử dụng Parameterized Query / ORM Object:\n"
                    "models.User.findOne({\n"
                    "  where: {\n"
                    "    email: req.body.email,\n"
                    "    password: security.hash(req.body.password),\n"
                    "    deletedAt: null\n"
                    "  }\n"
                    "});"
                )
            },
            {
                "name": "Search Products SQLi (Christmas Special)",
                "difficulty": 3,
                "category": "Injection",
                "endpoint": "GET /rest/products/search?q=",
                "description": "Khai thác SQLi qua thanh tìm kiếm sản phẩm để truy vấn các sản phẩm bị ẩn hoặc đọc cấu trúc bảng SQLite.",
                "attack_vector": "q=apple')) UNION SELECT null, id, email, password, null, null, null, null, null FROM Users--",
                "root_cause_file": "routes/search.ts",
                "vulnerable_code": (
                    "// routes/search.ts\n"
                    "models.sequelize.query(\n"
                    "  `SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`\n"
                    ");"
                ),
                "remediated_code": (
                    "// Sử dụng replacements tham số hóa an toàn:\n"
                    "models.sequelize.query(\n"
                    "  'SELECT * FROM Products WHERE ((name LIKE :search OR description LIKE :search) AND deletedAt IS NULL) ORDER BY name',\n"
                    "  { replacements: { search: `%${criteria}%` }, model: models.Product }\n"
                    ");"
                )
            }
        ],
        "defense_strategies": [
            "Sử dụng Parameterized Queries (Prepared Statements) hoặc Object-Relational Mapping (ORM) an toàn.",
            "Áp dụng nguyên tắc đặc quyền tối thiểu (Least Privilege) cho tài khoản kết nối Database.",
            "Xác thực và chuẩn hóa đầu vào nghiêm ngặt bằng Whitelist.",
            "Bật Web Application Firewall (WAF) để ngăn chặn các mẫu injection thông dụng."
        ]
    },
    {
        "id": "xss",
        "name": "Cross-Site Scripting (XSS)",
        "cwe": "CWE-79: Improper Neutralization of Input During Web Page Generation",
        "owasp_category": "A03:2021 - Injection",
        "severity": "HIGH",
        "cvss": 8.2,
        "portswigger_summary": (
            "XSS xảy ra khi ứng dụng web nhận dữ liệu không đáng tin cậy và hiển thị lại trên trình duyệt mà không "
            "lọc hoặc mã hóa đúng ngữ cảnh. PortSwigger phân loại XSS thành: Reflected XSS (phản xạ qua URL/Request), "
            "Stored XSS (lưu trữ trong Database) và DOM-based XSS (xảy ra hoàn toàn tại Client do xử lý DOM không an toàn)."
        ),
        "mechanism": (
            "Dữ liệu người dùng được đưa vào DOM thông qua các 'Source' (location.search, document.referrer, input) "
            "và đẩy vào các 'Sink' thực thi JavaScript nguy hiểm (innerHTML, eval, document.write) hoặc "
            "Angular bypassSecurityTrustHtml mà không có bộ lọc khử khuẩn (Sanitization)."
        ),
        "detection_vectors": [
            "DOM Sink: <iframe src=\"javascript:alert(`xss`)\">",
            "Event Handler: <img src=x onerror=alert(1)>",
            "Angular Template Expression: {{constructor.constructor('alert(1)')()}}",
            "SVG Vector: <svg onload=alert(document.domain)>"
        ],
        "juice_shop_challenges": [
            {
                "name": "DOM XSS",
                "difficulty": 1,
                "category": "XSS",
                "endpoint": "GET /#/search?q=",
                "description": "Thực thi mã JavaScript trong bối cảnh phiên làm việc của người dùng thông qua ô tìm kiếm.",
                "attack_vector": "<iframe src=\"javascript:alert(`xss`)\"> chèn vào ô tìm kiếm sản phẩm.",
                "root_cause_file": "frontend/src/app/search-result/search-result.component.ts",
                "vulnerable_code": (
                    "// Frontend Angular component dùng bypassSecurityTrustHtml:\n"
                    "this.searchValue = this.sanitizer.bypassSecurityTrustHtml(\n"
                    "  this.route.snapshot.queryParams['q']\n"
                    ");"
                ),
                "remediated_code": (
                    "// Không bypass cơ chế bảo vệ mặc định của Angular:\n"
                    "// Giữ nguyên chuỗi dạng text thuần (Angular mặc định mã hóa HTML entities):\n"
                    "this.searchValue = this.route.snapshot.queryParams['q'];\n"
                    "// Nếu bắt buộc render HTML, sử dụng thư viện DOMPurify:\n"
                    "import DOMPurify from 'dompurify';\n"
                    "this.safeHtml = DOMPurify.sanitize(userInput);"
                )
            },
            {
                "name": "Persistent XSS (Customer Feedback)",
                "difficulty": 2,
                "category": "XSS",
                "endpoint": "POST /api/Feedbacks",
                "description": "Lưu trữ mã script độc hại vào phần phản hồi khách hàng để kích hoạt khi Quản trị viên duyệt đánh giá.",
                "attack_vector": "<<SCRIPT>alert(\"xss\");//<</SCRIPT>",
                "root_cause_file": "routes/feedback.ts",
                "vulnerable_code": (
                    "// Lưu trực tiếp feedback vào CSDL mà không mã hóa ngữ cảnh hiển thị:\n"
                    "models.Feedback.create({\n"
                    "  comment: req.body.comment,\n"
                    "  rating: req.body.rating\n"
                    "});"
                ),
                "remediated_code": (
                    "// Làm sạch dữ liệu trước khi lưu và hiển thị bằng HTML encoding / DOMPurify:\n"
                    "const cleanComment = DOMPurify.sanitize(req.body.comment);\n"
                    "models.Feedback.create({ comment: cleanComment, rating: req.body.rating });"
                )
            }
        ],
        "defense_strategies": [
            "Áp dụng chính sách Content Security Policy (CSP) chặt chẽ (hạn chế inline scripts, cấm unsafe-eval).",
            "Mã hóa ngữ cảnh đầu ra (Context-aware Output Encoding: HTML, Attribute, JavaScript, CSS).",
            "Tận dụng cơ chế tự động escape của các Framework hiện đại (Angular, React, Vue).",
            "Đặt cờ HttpOnly cho các cookie nhạy cảm để ngăn chặn đánh cắp cookie qua XSS."
        ]
    },
    {
        "id": "broken_access_control",
        "name": "Broken Access Control & IDOR",
        "cwe": "CWE-284: Improper Access Control / CWE-639: Insecure Direct Object References",
        "owasp_category": "A01:2021 - Broken Access Control",
        "severity": "CRITICAL",
        "cvss": 9.1,
        "portswigger_summary": (
            "Kiểm soát truy cập là cơ chế đảm bảo người dùng chỉ được thao tác trong phạm vi quyền hạn được cấp. "
            "PortSwigger phân loại lỗi này thành: Leo quyền ngang (Horizontal Privilege Escalation / IDOR) và "
            "Leo quyền dọc (Vertical Privilege Escalation). Khiếm khuyết này dẫn đến tiết lộ thông tin người khác, "
            "chỉnh sửa dữ liệu trái phép hoặc chiếm đoạt vai trò quản trị."
        ),
        "mechanism": (
            "Ứng dụng tin cậy mù quáng vào các định danh đối tượng (ID, username, role) do client gửi lên trong "
            "tham số URL, body JSON hoặc header mà không đối chiếu với phiên đăng nhập của người dùng được xác thực "
            "ở phía máy chủ."
        ),
        "detection_vectors": [
            "Thay đổi tham số ID: GET /rest/basket/1 -> GET /rest/basket/2",
            "Truy cập trực tiếp đường dẫn ẩn: GET /#/administration hoặc GET /api-docs",
            "Thao túng HTTP Verb: Sử dụng PUT/DELETE thay vì GET đối với tài nguyên nhạy cảm",
            "Thao túng thuộc tính phân quyền trong JSON: {\"role\": \"admin\"}"
        ],
        "juice_shop_challenges": [
            {
                "name": "View Basket (IDOR)",
                "difficulty": 2,
                "category": "Broken Access Control",
                "endpoint": "GET /rest/basket/:id",
                "description": "Xem giỏ hàng của bất kỳ người dùng nào bằng cách đổi ID giỏ hàng trên URL.",
                "attack_vector": "Thay thế basketId trong token/request từ ID của mình (ví dụ 1) thành ID của Admin (ví dụ 2).",
                "root_cause_file": "routes/basket.ts",
                "vulnerable_code": (
                    "// routes/basket.ts\n"
                    "// Ứng dụng chỉ lấy ID từ URL mà KHÔNG kiểm tra ID đó có thuộc về user đang đăng nhập không:\n"
                    "models.Basket.findOne({ where: { id: req.params.id } })\n"
                    "  .then(basket => res.json({ status: 'success', data: basket }));"
                ),
                "remediated_code": (
                    "// Kiểm tra quyền sở hữu dựa trên Session / Token đã xác thực:\n"
                    "const currentUserId = req.user.id;\n"
                    "models.Basket.findOne({ where: { id: req.params.id, UserId: currentUserId } })\n"
                    "  .then(basket => {\n"
                    "    if (!basket) return res.status(403).json({ error: 'Truy cập bị từ chối' });\n"
                    "    res.json({ status: 'success', data: basket });\n"
                    "  });"
                )
            },
            {
                "name": "Admin Section Exposure",
                "difficulty": 2,
                "category": "Broken Access Control",
                "endpoint": "GET /#/administration",
                "description": "Truy cập giao diện quản trị bằng cách điều hướng trực tiếp trên Single Page Application (SPA).",
                "attack_vector": "Gõ trực tiếp đường dẫn URL `/#/administration` trên trình duyệt do Route Guard của Angular thiếu xác thực server-side.",
                "root_cause_file": "frontend/src/app/app.routing.ts",
                "vulnerable_code": (
                    "// Định nghĩa route ở Client mà thiếu Server-side API gateway enforce:\n"
                    "{ path: 'administration', component: AdministrationComponent }"
                ),
                "remediated_code": (
                    "// Thêm Route Guard ở Frontend và BẮT BUỘC kiểm tra Role Admin ở mọi API Backend:\n"
                    "// Backend Middleware:\n"
                    "function requireAdmin(req, res, next) {\n"
                    "  if (req.user && req.user.role === 'admin') return next();\n"
                    "  return res.status(403).json({ error: 'Yêu cầu quyền Quản trị viên' });\n"
                    "}"
                )
            }
        ],
        "defense_strategies": [
            "Triển khai kiểm soát truy cập tập trung tại Server-side cho mọi API endpoint (Deny by Default).",
            "Không bao giờ tin tưởng định danh ID truyền từ Client; luôn ánh xạ qua Token/Session xác thực.",
            "Sử dụng Indirect Reference Maps hoặc GUID/UUID khó đoán nếu cần bảo vệ ID đối tượng.",
            "Ghi log đầy đủ các sự kiện kiểm soát truy cập thất bại để cảnh báo xâm nhập."
        ]
    },
    {
        "id": "path_traversal",
        "name": "Path Traversal & Arbitrary File Access",
        "cwe": "CWE-22: Improper Limitation of a Pathname to a Restricted Directory",
        "owasp_category": "A01:2021 - Broken Access Control",
        "severity": "HIGH",
        "cvss": 7.5,
        "portswigger_summary": (
            "Path Traversal (còn gọi là Directory Traversal) cho phép kẻ tấn công đọc các tệp tin tùy ý trên máy chủ "
            "lưu trữ ứng dụng. Điều này có thể bao gồm mã nguồn ứng dụng, cấu hình nhạy cảm, thông tin đăng nhập CSDL "
            "hoặc các tệp hệ điều hành nhạy cảm như /etc/passwd hoặc file sao lưu backup."
        ),
        "mechanism": (
            "Ứng dụng truyền trực tiếp tham số tên tệp do người dùng cung cấp vào các hàm xử lý tệp (fs.readFile, "
            "res.sendFile) mà không kiểm tra ký tự điều hướng thư mục ('../' hoặc '..\\') hoặc sử dụng kỹ thuật "
            "bypass như URL-encoding (%2e%2e%2f) hoặc Poison Null Byte (%00)."
        ),
        "detection_vectors": [
            "Payload cơ bản: ../../etc/passwd hoặc ..\\..\\windows\\win.ini",
            "Poison Null Byte (cho các phiên bản kiểm tra đuôi mở rộng): ../eastere.gg%2500.md",
            "URL Encoded: ..%252f..%252fpackage.json.bak"
        ],
        "juice_shop_challenges": [
            {
                "name": "Confidential Document / Easter Egg",
                "difficulty": 3,
                "category": "Vulnerable Components / Path Traversal",
                "endpoint": "GET /ftp/:file",
                "description": "Tải các tệp tài liệu nội bộ và mã nguồn bị cấm trong thư mục /ftp thông qua kỹ thuật vượt kiểm tra đuôi tệp.",
                "attack_vector": "GET /ftp/eastere.gg%2500.md hoặc /ftp/package.json.bak%2500.md",
                "root_cause_file": "routes/fileServer.ts",
                "vulnerable_code": (
                    "// routes/fileServer.ts (Juice Shop)\n"
                    "// Chỉ kiểm tra file kết thúc bằng .md hoặc .pdf bằng hàm endsWith:\n"
                    "if (file && (file.endsWith('.md') || file.endsWith('.pdf'))) {\n"
                    "  res.sendFile(path.resolve('ftp/', file));\n"
                    "} else {\n"
                    "  res.status(403).send('Only .md and .pdf files are allowed!');\n"
                    "}"
                ),
                "remediated_code": (
                    "// Kiểm tra chuẩn hóa đường dẫn và dùng Whitelist tên tệp:\n"
                    "const safeDir = path.resolve(__dirname, '../public/ftp');\n"
                    "const safePath = path.normalize(path.join(safeDir, path.basename(file)));\n"
                    "if (!safePath.startsWith(safeDir) || !isAllowedFile(file)) {\n"
                    "  return res.status(403).send('Truy cập tệp tin bị cấm');\n"
                    "}\n"
                    "res.sendFile(safePath);"
                )
            }
        ],
        "defense_strategies": [
            "Tránh truyền trực tiếp đầu vào người dùng vào các API hệ thống tệp tin.",
            "Sử dụng danh sách trắng (Whitelist) các tệp tin và thư mục được phép truy cập.",
            "Chuẩn hóa đường dẫn (Canonicalization) và xác thực đường dẫn tuyệt đối phải nằm trong thư mục gốc cho phép.",
            "Chạy ứng dụng trong môi trường sandbox với đặc quyền hệ điều hành tối thiểu (chroot / docker non-root)."
        ]
    },
    {
        "id": "jwt_auth_flaws",
        "name": "Authentication & JWT Vulnerabilities",
        "cwe": "CWE-287: Improper Authentication / CWE-347: Improper Verification of Cryptographic Signature",
        "owasp_category": "A07:2021 - Identification and Authentication Failures",
        "severity": "CRITICAL",
        "cvss": 9.3,
        "portswigger_summary": (
            "JSON Web Tokens (JWT) thường được dùng để duy trì trạng thái đăng nhập trong các ứng dụng web và API. "
            "PortSwigger chỉ ra các lỗ hổng phổ biến của JWT: Chấp nhận thuật toán None (None Algorithm), "
            "Khóa bí mật HMAC yếu dễ bị vét cạn (Weak Secret Brute-forcing), Lỗi tráo đổi khóa (Key Confusion - RSA sang HMAC) "
            "và Thiếu kiểm tra thời hạn hết hạn (exp claim)."
        ),
        "mechanism": (
            "Thư viện JWT kiểm tra tính hợp lệ của chữ ký dựa trên trường 'alg' trong Header của Token do Client gửi lên. "
            "Nếu lập trình viên cho phép thuật toán 'none' hoặc sử dụng khóa bí mật mặc định, kẻ tấn công có thể giả mạo "
            "bất kỳ thông tin định danh nào (ví dụ email: admin@juice-sh.op)."
        ),
        "detection_vectors": [
            "Thay đổi alg thành 'none' trong JWT Header: {\"alg\":\"none\",\"typ\":\"JWT\"}",
            "Khai thác khóa bí mật yếu: vét cạn bằng hashcat/john với wordlist (secret, admin, juice-shop)",
            "Chèn khóa công khai làm khóa bí mật đối xứng HMAC"
        ],
        "juice_shop_challenges": [
            {
                "name": "Forged Feedback / Admin Token Impersonation",
                "difficulty": 3,
                "category": "Broken Authentication",
                "endpoint": "Authorization: Bearer <jwt_token>",
                "description": "Giả mạo Token của Quản trị viên để thực hiện các thao tác đòi hỏi quyền hạn cao cấp.",
                "attack_vector": "Tạo JWT mới với payload role='admin' và ký bằng khóa HMAC bí mật yếu được tìm thấy hoặc thiết lập alg: 'none'.",
                "root_cause_file": "lib/insecurity.ts",
                "vulnerable_code": (
                    "// lib/insecurity.ts (Juice Shop)\n"
                    "// Khóa bí mật JWT được hardcode dạng chuỗi cố định và đơn giản:\n"
                    "const defaultSecret = 'your-secret-key-wants-to-be-secure';\n"
                    "jwt.verify(token, publicKey, { algorithms: ['RS256', 'HS256', 'none'] });"
                ),
                "remediated_code": (
                    "// Nghiêm cấm thuật toán 'none' và sử dụng cặp khóa bất đối xứng (RS256/ES256) an toàn:\n"
                    "const verified = jwt.verify(token, process.env.JWT_PUBLIC_KEY, {\n"
                    "  algorithms: ['RS256'], // Chỉ chấp nhận RS256\n"
                    "  issuer: 'auth.juiceshop.corp',\n"
                    "  audience: 'api.juiceshop.corp'\n"
                    "});"
                )
            }
        ],
        "defense_strategies": [
            "Không bao giờ chấp nhận header có alg: 'none' trong quá trình xác thực JWT.",
            "Sử dụng khóa bí mật có độ phức tạp cao (ít nhất 256 bits ngẫu nhiên) hoặc mã hóa bất đối xứng RS256/EdDSA.",
            "Lưu trữ khóa bí mật trong HSM (Hardware Security Module) hoặc Secret Manager, không đưa vào mã nguồn.",
            "Kiểm tra đầy đủ các claims tiêu chuẩn: exp (expiration), iss (issuer), aud (audience)."
        ]
    },
    {
        "id": "ssrf",
        "name": "Server-Side Request Forgery (SSRF)",
        "cwe": "CWE-918: Server-Side Request Forgery (SSRF)",
        "owasp_category": "A10:2021 - Server-Side Request Forgery (SSRF)",
        "severity": "HIGH",
        "cvss": 8.6,
        "portswigger_summary": (
            "SSRF là lỗ hổng an ninh cho phép kẻ tấn công điều khiển máy chủ ứng dụng web gửi các yêu cầu HTTP giả mạo "
            "tới các hệ thống nội bộ bên trong hạ tầng mạng mà kẻ tấn công không thể truy cập trực tiếp từ Internet. "
            "PortSwigger nhấn mạnh nguy cơ SSRF trong việc khai thác Cloud Metadata API (như AWS EC2 IMDSv1 169.254.169.254) "
            "để đánh cắp quyền truy cập đám mây."
        ),
        "mechanism": (
            "Ứng dụng cung cấp tính năng tải tài nguyên từ xa (ví dụ: nhập URL ảnh đại diện, webhook, xem trước liên kết). "
            "Máy chủ nhận URL từ người dùng và trực tiếp gửi request mà không kiểm tra địa chỉ IP đích có phải là IP "
            "cục bộ (Loopback 127.0.0.1) hay dải IP riêng tư (RFC 1918 10.0.0.0/8, 192.168.0.0/16)."
        ),
        "detection_vectors": [
            "Loopback access: http://127.0.0.1:3000 hoặc http://localhost:8080",
            "Cloud Metadata: http://169.254.169.254/latest/meta-data/",
            "DNS Rebinding / Alternate IP format: http://2130706433 (dạng số nguyên của 127.0.0.1)"
        ],
        "juice_shop_challenges": [
            {
                "name": "SSRF (Profile Image / B2B Order)",
                "difficulty": 4,
                "category": "SSRF",
                "endpoint": "POST /profile/image/url",
                "description": "Yêu cầu máy chủ Juice Shop truy xuất ảnh từ một địa chỉ URL nội bộ trái phép.",
                "attack_vector": "imageUrl: \"http://127.0.0.1:3000/rest/admin/application-configuration\"",
                "root_cause_file": "routes/profileImageUrlUpload.ts",
                "vulnerable_code": (
                    "// routes/profileImageUrlUpload.ts\n"
                    "// Máy chủ dùng request/needle tải thẳng URL do người dùng chỉ định:\n"
                    "needle('get', req.body.imageUrl)\n"
                    "  .then(response => fs.writeFile(targetPath, response.body));"
                ),
                "remediated_code": (
                    "// Phân giải DNS và kiểm tra địa chỉ IP đích trước khi tạo kết nối:\n"
                    "const ip = await dns.promises.lookup(parsedUrl.hostname);\n"
                    "if (isPrivateIP(ip.address)) {\n"
                    "  throw new Error('Từ chối truy cập dải mạng nội bộ (SSRF Protection)');\n"
                    "}\n"
                    "// Chỉ cho phép giao thức HTTPS và domain trong danh sách an toàn:"
                )
            }
        ],
        "defense_strategies": [
            "Áp dụng danh sách trắng (Whitelist) nghiêm ngặt cho tên miền và lược đồ giao thức (chỉ cho phép https://).",
            "Vô hiệu hóa chuyển hướng HTTP (Disable HTTP Redirections) trong HTTP client.",
            "Kiểm tra và ngăn chặn kết nối tới tất cả các dải IP nội bộ (127.0.0.1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.169.254).",
            "Phân tách vùng mạng (Network Segmentation), đặt ứng dụng web trong DMZ không có quyền kết nối trực tiếp đến các dịch vụ nhạy cảm nội bộ."
        ]
    },
    {
        "id": "security_misconfig",
        "name": "Security Misconfiguration & Information Disclosure",
        "cwe": "CWE-200: Exposure of Sensitive Information / CWE-16: Configuration",
        "owasp_category": "A05:2021 - Security Misconfiguration",
        "severity": "MEDIUM",
        "cvss": 6.5,
        "portswigger_summary": (
            "Cấu hình sai bảo mật xảy ra khi các biện pháp kiểm soát bảo mật bị thiếu sót, cài đặt không an toàn "
            "hoặc giữ nguyên cấu hình mặc định của nhà sản xuất. Lỗ hổng này tiết lộ thông tin nhạy cảm của hệ thống "
            "(thông tin lỗi chi tiết, mã nguồn, cấu hình CSDL, file robots.txt, Swagger documentation) hỗ trợ đắc lực "
            "cho kẻ tấn công trong giai đoạn trinh sát."
        ),
        "mechanism": (
            "Ứng dụng để chế độ Debug trong môi trường sản xuất, không thiết lập các HTTP Security Headers tiêu chuẩn "
            "(CSP, HSTS, X-Frame-Options), để lộ các tệp sao lưu (backup files, .git, package.json.bak) và các API docs công khai."
        ),
        "detection_vectors": [
            "Kiểm tra tệp tin ẩn: GET /robots.txt, GET /package.json.bak, GET /.git/config",
            "Kích hoạt lỗi hệ thống để xem Stack Trace: gửi ký tự lỗi JSON vào API",
            "Kiểm tra tài liệu API: GET /api-docs hoặc GET /swagger.json"
        ],
        "juice_shop_challenges": [
            {
                "name": "Error Handling (Stack Trace Leak)",
                "difficulty": 1,
                "category": "Security Misconfiguration",
                "endpoint": "GET /rest/products/search?q='",
                "description": "Kích hoạt lỗi SQL/Runtime để ứng dụng trả về toàn bộ thông điệp lỗi SQLite và ngăn xếp lời gọi (stack trace).",
                "attack_vector": "Truy vấn chuỗi đặc biệt gây lỗi cú pháp CSDL, nhận phản hồi chứa chi tiết bảng và thư mục nội bộ máy chủ.",
                "root_cause_file": "server.ts",
                "vulnerable_code": (
                    "// Express error handler trả trực tiếp error stack ra client:\n"
                    "app.use((err, req, res, next) => {\n"
                    "  res.status(500).json({ error: err.message, stack: err.stack });\n"
                    "});"
                ),
                "remediated_code": (
                    "// Ẩn chi tiết lỗi với người dùng, chỉ ghi log an toàn tại server:\n"
                    "app.use((err, req, res, next) => {\n"
                    "  logger.error(err); // Ghi log nội bộ\n"
                    "  res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống. Vui lòng liên hệ quản trị viên.' });\n"
                    "});"
                )
            },
            {
                "name": "Exposed Metrics / API Docs",
                "difficulty": 2,
                "category": "Information Disclosure",
                "endpoint": "GET /api-docs/ và GET /metrics",
                "description": "Để lộ tài liệu API Swagger và số liệu Prometheus metrics mà không có xác thực.",
                "attack_vector": "Truy cập trực tiếp đường dẫn /api-docs/ để xem toàn bộ cấu trúc các API ẩn của hệ thống.",
                "root_cause_file": "server.ts",
                "vulnerable_code": (
                    "// server.ts\n"
                    "app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));"
                ),
                "remediated_code": (
                    "// Bắt buộc xác thực quyền Admin trước khi hiển thị tài liệu API hoặc chỉ bật ở môi trường dev:\n"
                    "if (process.env.NODE_ENV === 'development') {\n"
                    "  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));\n"
                    "}"
                )
            }
        ],
        "defense_strategies": [
            "Vô hiệu hóa tính năng hiển thị lỗi chi tiết (Stack Trace) trên môi trường Production.",
            "Cấu hình đầy đủ các tiêu đề an ninh HTTP (Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options, X-Frame-Options).",
            "Bảo vệ các endpoint quản trị và tài liệu API (/api-docs, /metrics) bằng lớp xác thực mạnh.",
            "Tự động hóa kiểm tra cấu hình an ninh định kỳ bằng các công cụ SAST và DAST."
        ]
    },
    {
        "id": "xxe",
        "name": "XML External Entity (XXE) Injection",
        "cwe": "CWE-611: Improper Restriction of XML External Entity Reference",
        "owasp_category": "A05:2021 - Security Misconfiguration",
        "severity": "HIGH",
        "cvss": 8.2,
        "portswigger_summary": (
            "XXE là lỗ hổng an ninh cho phép kẻ tấn công can thiệp vào quá trình xử lý dữ liệu XML của ứng dụng. "
            "PortSwigger chỉ ra rằng việc trình phân tích XML xử lý các thực thể ngoài (External Entities) có thể dẫn đến "
            "đọc trộm tệp máy chủ cục bộ, tấn công SSRF vào mạng nội bộ, hoặc gây cạn kiệt tài nguyên từ chối dịch vụ (Billion Laughs Attack)."
        ),
        "mechanism": (
            "Trình phân tích cú pháp XML cho phép khai báo DTD (Document Type Definition) chứa thực thể bên ngoài `SYSTEM \"file:///...\"` "
            "mà không tắt tính năng external entity parsing hoặc external DTD loading."
        ),
        "detection_vectors": [
            "Đọc file cục bộ: <!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]><foo>&xxe;</foo>",
            "SSRF qua XXE: <!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"http://169.254.169.254/\"> ]>",
            "Billion Laughs DoS: Khai báo entity đệ quy lồng nhau gây tràn bộ nhớ."
        ],
        "juice_shop_challenges": [
            {
                "name": "XXE Data Access (B2B Customer Order)",
                "difficulty": 3,
                "category": "XXE Injection",
                "endpoint": "POST /file-upload (B2B XML upload)",
                "description": "Tải lên tệp XML chứa entity độc hại để đọc nội dung tệp hệ thống trên máy chủ Juice Shop.",
                "attack_vector": "<?xml version=\"1.0\"?><!DOCTYPE order [<!ENTITY file SYSTEM \"file:///etc/passwd\">]><order>&file;</order>",
                "root_cause_file": "routes/b2bOrder.ts",
                "vulnerable_code": (
                    "// routes/b2bOrder.ts (Juice Shop)\n"
                    "// Sử dụng thư viện libxmljs với cấu hình noent: true (cho phép thay thế entity):\n"
                    "const xmlDoc = libxmljs.parseXml(req.body, { noent: true, noblanks: true });"
                ),
                "remediated_code": (
                    "// Tắt hoàn toàn tính năng thay thế External Entity trong bộ phân tích cú pháp XML:\n"
                    "const xmlDoc = libxmljs.parseXml(req.body, {\n"
                    "  noent: false,     // Tắt entity substitution\n"
                    "  nonet: true       // Cấm truy cập mạng bên ngoài trong XML\n"
                    "});"
                )
            }
        ],
        "defense_strategies": [
            "Vô hiệu hóa hoàn toàn DTD (External Entities) trong tất cả các bộ phân tích XML của ứng dụng.",
            "Ưu tiên sử dụng các định dạng dữ liệu ít phức tạp hơn như JSON nếu không bắt buộc dùng XML.",
            "Cập nhật các thư viện phân tích XML lên phiên bản mới nhất đã được vá lỗi bảo mật mặc định."
        ]
    },
    {
        "id": "insecure_deserialization",
        "name": "Insecure Deserialization & Code Injection",
        "cwe": "CWE-502: Deserialization of Untrusted Data",
        "owasp_category": "A08:2021 - Software and Data Integrity Failures",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "portswigger_summary": (
            "Giải tuần tự hóa không an toàn xảy ra khi ứng dụng chuyển đổi dữ liệu dạng chuỗi (byte stream, JSON, binary) "
            "ngược trở lại thành đối tượng lập trình mà không kiểm chứng. PortSwigger phân tích kỹ thuật này có thể dẫn đến "
            "thực thi mã từ xa (Remote Code Execution - RCE) thông qua Gadget Chains hoặc các hàm thực thi động."
        ),
        "mechanism": (
            "Trong môi trường Node.js/JavaScript, việc sử dụng các thư viện như `node-serialize` cho phép khôi phục hàm "
            "với ký hiệu `_$$ND_FUNC$$_` dẫn đến tự động thực thi hàm ngay khi giải mã (IIFE - Immediately Invoked Function Expression)."
        ),
        "detection_vectors": [
            "Node-serialize IIFE payload: {\"rce\":\"_$$ND_FUNC$$_function(){ require('child_process').execSync('id'); }()\"}",
            "Python Pickle payload, Java ysoserial gadget chains"
        ],
        "juice_shop_challenges": [
            {
                "name": "Nested Easter Egg / RCE via Deserialization",
                "difficulty": 4,
                "category": "Insecure Deserialization",
                "endpoint": "POST /rest/basket/:id/order (hoặc upload profile)",
                "description": "Thực thi mã tùy ý trên máy chủ thông qua giải mã chuỗi đối tượng độc hại.",
                "attack_vector": "Chuỗi JSON chứa hàm IIFE mã hóa base64 truyền vào trường cookie hoặc body xử lý bởi serialize.",
                "root_cause_file": "routes/b2bOrder.ts",
                "vulnerable_code": (
                    "// Giải mã đối tượng từ người dùng không an toàn:\n"
                    "const serialize = require('node-serialize');\n"
                    "const obj = serialize.unserialize(untrustedInput);"
                ),
                "remediated_code": (
                    "// Không bao giờ tuần tự hóa/giải tuần tự hóa hàm thực thi; chỉ sử dụng JSON.parse an toàn:\n"
                    "try {\n"
                    "  const safeObj = JSON.parse(untrustedInput);\n"
                    "} catch (e) {\n"
                    "  res.status(400).send('Dữ liệu JSON không hợp lệ');\n"
                    "}"
                )
            }
        ],
        "defense_strategies": [
            "Không bao giờ giải tuần tự hóa dữ liệu từ nguồn không tin cậy bằng các cơ chế hỗ trợ khôi phục code.",
            "Chỉ sử dụng các định dạng tuần tự hóa dữ liệu thuần túy (như chuẩn JSON tiêu chuẩn).",
            "Nếu bắt buộc phải giải mã đối tượng phức tạp, sử dụng chữ ký số (Digital Signature/HMAC) để xác thực tính toàn vẹn trước khi xử lý."
        ]
    },
    {
        "id": "csrf",
        "name": "Cross-Site Request Forgery (CSRF)",
        "cwe": "CWE-352: Cross-Site Request Forgery",
        "owasp_category": "A01:2021 - Broken Access Control",
        "severity": "MEDIUM",
        "cvss": 6.8,
        "portswigger_summary": (
            "CSRF là kỹ thuật tấn công lừa nạn nhân gửi các yêu cầu HTTP ngoài ý muốn tới một ứng dụng mà họ đã đăng nhập. "
            "PortSwigger nhấn mạnh điều kiện cần: Hành động có ý nghĩa thay đổi trạng thái, Xác thực dựa trên Cookie được trình duyệt "
            "tự động gửi kèm, và Thiếu tham số ngẫu nhiên không thể dự đoán (Anti-CSRF Token)."
        ),
        "mechanism": (
            "Trình duyệt người dùng tự động đính kèm Cookie phiên đăng nhập mỗi khi gửi request đến trang web đích. "
            "Trang web của kẻ tấn công chứa form ẩn tự động POST (Auto-submitting form) khiến máy chủ tưởng rằng đây là yêu cầu hợp lệ từ người dùng."
        ),
        "detection_vectors": [
            "Tạo PoC HTML form: <form action=\"http://target/change-password\" method=\"POST\"><input type=\"hidden\" name=\"pass\" value=\"123456\"></form><script>document.forms[0].submit()</script>",
            "Kiểm tra Cookie có thiếu thuộc tính SameSite (SameSite=None mà không có cờ phòng thủ)"
        ],
        "juice_shop_challenges": [
            {
                "name": "CSRF / Cross-Origin Password Change",
                "difficulty": 3,
                "category": "CSRF",
                "endpoint": "GET /rest/user/change-password?new=xxx",
                "description": "Thay đổi mật khẩu tài khoản người dùng khi họ truy cập vào một trang web độc hại liên kết ngoài.",
                "attack_vector": "Dụ người dùng truy cập trang HTML chứa thẻ <img src=\"http://localhost:3000/rest/user/change-password?new=hacked\">",
                "root_cause_file": "routes/changePassword.ts",
                "vulnerable_code": (
                    "// routes/changePassword.ts\n"
                    "// Cho phép đổi mật khẩu qua phương thức GET hoặc POST mà không có Anti-CSRF Token:\n"
                    "app.get('/rest/user/change-password', (req, res) => {\n"
                    "  // Cập nhật mật khẩu ngay khi nhận request GET có cookie phiên\n"
                    "});"
                ),
                "remediated_code": (
                    "// Đổi sang phương thức POST, sử dụng Anti-CSRF Token và Cookie SameSite=Strict:\n"
                    "app.post('/rest/user/change-password', csrfProtection, (req, res) => {\n"
                    "  // Chỉ xử lý khi token CSRF hợp lệ và kiểm tra mật khẩu cũ (Re-authentication)\n"
                    "});"
                )
            }
        ],
        "defense_strategies": [
            "Thiết lập thuộc tính `SameSite=Strict` hoặc `SameSite=Lax` cho mọi Session Cookies.",
            "Triển khai Anti-CSRF Tokens (Synchronizer Token Pattern hoặc Double Submit Cookie).",
            "Sử dụng Custom Request Headers (như `X-Requested-With` hoặc `Authorization: Bearer <token>`) mà trình duyệt không tự động gửi qua Cross-Origin.",
            "Yêu cầu nhập lại mật khẩu hiện tại (Re-authentication) trước các hành động trọng yếu (đổi mật khẩu, chuyển khoản)."
        ]
    }
]

def get_all_vulnerabilities():
    return PORTSWIGGER_VULNERABILITIES

def get_vulnerability_by_id(vuln_id):
    for v in PORTSWIGGER_VULNERABILITIES:
        if v["id"] == vuln_id:
            return v
    return None
