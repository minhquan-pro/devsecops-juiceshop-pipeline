# Mô tả dự án của nhóm 9

## Thành viên nhóm
- Lê Minh Quân
- Nguyễn Gia Hào
- Nguyễn Đình Ngọc
- Nguyễn Thế Dương

## Tên đề tài
Xây dựng và đánh giá bảo mật một pipeline DevSecOps end-to-end cho **OWASP Juice Shop**

## Mô tả
OWASP Juice Shop là một ứng dụng web (Node.js/Angular) được OWASP xây dựng sẵn với hàng loạt lỗ hổng bảo mật cố ý (SQL Injection, XSS, Broken Authentication, IDOR, v.v.), thường được dùng để luyện tập kiểm thử bảo mật.

Nhóm sẽ deploy ứng dụng này lên **AWS** (ECS Fargate hoặc Elastic Beanstalk), sau đó xây dựng một pipeline CI/CD tích hợp đầy đủ các bước kiểm tra bảo mật tự động (DevSecOps), nhằm phát hiện và đánh giá lỗ hổng ở nhiều lớp khác nhau:

- **SCA (Software Composition Analysis):** quét thư viện/dependency lỗi thời, CVE — OWASP Dependency-Check, Trivy/Snyk
- **SAST (Static Application Security Testing):** quét mã nguồn tĩnh — Semgrep, SonarQube
- **Container/Image scan:** quét lỗ hổng trong Docker image — Trivy, Grype
- **DAST (Dynamic Application Security Testing):** quét lỗ hổng runtime khi ứng dụng đang chạy — OWASP ZAP
- **IaC scan:** quét cấu hình hạ tầng (Dockerfile, Terraform/CloudFormation) — Trivy config, Checkov

Kết quả từ các bước quét sẽ được tổng hợp thành báo cáo, đối chiếu với OWASP Top 10 và đề xuất hướng khắc phục.

## Kiến trúc & công nghệ dự kiến
- **Target app:** OWASP Juice Shop (Docker)
- **Cloud:** AWS (ECR, ECS Fargate)
- **CI/CD:** GitHub Actions (hoặc AWS CodePipeline/CodeBuild)
- **SAST:** Semgrep / SonarQube
- **SCA:** OWASP Dependency-Check / Trivy
- **Container scan:** Trivy / Grype
- **DAST:** OWASP ZAP

## Phân công công việc

| Thành viên | Vai trò | Nhiệm vụ chính |
|---|---|---|
| Thành viên 1 | Hạ tầng & Target App | Tạo repo GitHub, deploy Juice Shop lên AWS (ECS Fargate), viết Dockerfile/docker-compose, dựng khung CI/CD |
| Thành viên 2 | SAST + SCA | Tích hợp Semgrep/SonarQube, Dependency-Check/Trivy, cấu hình fail-build khi có lỗ hổng nghiêm trọng |
| Thành viên 3 | Container Security + DAST | Quét image bằng Trivy/Grype, tích hợp OWASP ZAP, tự động hóa scan trong pipeline |
| Thành viên 4 | Tổng hợp, đánh giá & báo cáo | Gom kết quả các tool, đánh giá hiệu quả pipeline, đề xuất khắc phục, chuẩn bị slide demo |

## Cấu trúc thư mục dự kiến
```
.
├── app/            # Source code OWASP Juice Shop (fork)
├── infra/          # Dockerfile, docker-compose, cấu hình AWS
├── pipeline/        # File cấu hình CI/CD (GitHub Actions/CodePipeline)
├── reports/         # Kết quả các lần quét bảo mật
└── README.md
```

## Mục tiêu đầu ra
- Pipeline CI/CD chạy tự động, tích hợp đầy đủ 5 lớp kiểm tra bảo mật
- Báo cáo tổng hợp các lỗ hổng phát hiện được, phân loại theo OWASP Top 10
- Đề xuất biện pháp khắc phục cho từng loại lỗ hổng
- Demo trực quan quá trình pipeline phát hiện lỗ hổng trên Juice Shop
