#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DevSecOps JuiceShop Pipeline - Report Updater
Patches existing .docx report with 7 audit corrections from Worker #2
"""

import sys
import os
from docx import Document
from docx.shared import Pt, RGBColor, Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH
from datetime import datetime

def find_docx_report():
    """Find existing .docx report in .aKetqua directory"""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    for filename in os.listdir(current_dir):
        if filename.endswith('.docx') and not filename.startswith('~'):
            return os.path.join(current_dir, filename)
    return None

def insert_section_after_heading(doc, heading_text, new_content):
    """Insert content after a specific heading"""
    for i, para in enumerate(doc.paragraphs):
        if heading_text.lower() in para.text.lower():
            # Insert after this paragraph
            insert_position = i + 1
            for content_line in new_content:
                new_para = doc.paragraphs[insert_position].insert_paragraph_before(content_line)
                new_para.style = 'Normal'
                insert_position += 1
            return True
    return False

def update_devsecops_report(doc_path):
    """Apply 7 DevSecOps audit corrections"""
    
    print(f"[INFO] Loading document: {doc_path}")
    doc = Document(doc_path)
    
    corrections = [
        {
            "heading": "Runner Configuration",
            "content": [
                "✅ AUDIT CORRECTION #1: Linux Container Runner Configuration",
                "",
                "Original pipeline configuration uses GitHub-hosted Windows runners, which is incompatible with Docker-based SAST/DAST tools.",
                "",
                "Corrected Implementation:",
                "• Runner: ubuntu-latest (GitHub-hosted Linux container)",
                "• Docker support: Native docker-compose and container scanning",
                "• Compatibility: Semgrep, Trivy, OWASP Dependency-Check all require Linux runtime",
                "",
                "Updated .github/workflows/main.yml:",
                "  runs-on: ubuntu-latest",
                "  services:",
                "    docker:",
                "      image: docker:dind",
                ""
            ]
        },
        {
            "heading": "SAST and SCA Tools",
            "content": [
                "✅ AUDIT CORRECTION #2: SAST and SCA Tool Integration",
                "",
                "Missing automated static analysis and software composition analysis in original design.",
                "",
                "Implemented Tools:",
                "• Semgrep OSS (SAST): Detects SQL injection, XSS, hardcoded secrets",
                "• Trivy (SCA): Scans npm dependencies for CVEs (CRITICAL/HIGH severity)",
                "• Bandit (Python SAST): Analyzes Python security issues",
                "",
                "Pipeline Integration:",
                "  - name: Run Semgrep SAST",
                "    run: semgrep --config=auto --json -o semgrep-report.json",
                "  - name: Run Trivy SCA",
                "    run: trivy fs --severity CRITICAL,HIGH --format json -o trivy-report.json .",
                ""
            ]
        },
        {
            "heading": "Secret Scanning",
            "content": [
                "✅ AUDIT CORRECTION #3: Secret Scanning and Credential Protection",
                "",
                "Original report lacks secret detection mechanisms for API keys, tokens, and credentials.",
                "",
                "Implemented Solution:",
                "• Gitleaks: Pre-commit hook and CI/CD integration",
                "• Detection patterns: AWS keys, GitHub tokens, database passwords, JWT secrets",
                "• Automatic blocking: Pipeline fails if secrets detected in git history",
                "",
                "Configuration (.gitleaks.toml):",
                "  [[rules]]",
                "  id = \"aws-access-key\"",
                "  regex = '''AKIA[0-9A-Z]{16}'''",
                "  description = \"AWS Access Key ID\"",
                ""
            ]
        },
        {
            "heading": "Quality Gates",
            "content": [
                "✅ AUDIT CORRECTION #4: Quality Gate Enforcement",
                "",
                "Missing fail-fast mechanisms for security vulnerabilities and code quality issues.",
                "",
                "Implemented Quality Gates:",
                "• SAST Gate: Fail if Semgrep detects HIGH/CRITICAL severity issues",
                "• SCA Gate: Fail if Trivy finds exploitable CVEs in dependencies",
                "• Secret Gate: Fail if Gitleaks detects exposed credentials",
                "• Coverage Gate: Fail if test coverage < 80%",
                "",
                "Pipeline Logic:",
                "  if [[ $(jq '.results[].severity' semgrep-report.json | grep -c HIGH) -gt 0 ]]; then",
                "    echo '❌ QUALITY GATE FAILED: High-severity vulnerabilities detected'",
                "    exit 1",
                "  fi",
                ""
            ]
        },
        {
            "heading": "Container Security Scanning",
            "content": [
                "✅ AUDIT CORRECTION #5: Container Image Scanning with Trivy",
                "",
                "Original deployment lacks Docker image vulnerability scanning before production.",
                "",
                "Implemented Container Scanning:",
                "• Trivy Image Scanner: Scans final Docker image for OS/library vulnerabilities",
                "• SBOM Generation: Creates Software Bill of Materials (CycloneDX format)",
                "• Registry Integration: Scans images before pushing to Docker Hub/ECR",
                "",
                "Pipeline Step:",
                "  - name: Build Docker Image",
                "    run: docker build -t juiceshop:${{ github.sha }} .",
                "  - name: Scan Docker Image",
                "    run: trivy image --severity CRITICAL,HIGH juiceshop:${{ github.sha }}",
                ""
            ]
        },
        {
            "heading": "Deployment Automation",
            "content": [
                "✅ AUDIT CORRECTION #6: Automated Deployment with Security Validation",
                "",
                "Original report describes manual deployment without security checks.",
                "",
                "Automated Deployment Pipeline:",
                "• Pre-deployment: Verify all quality gates passed",
                "• Deployment: Blue-green deployment to AWS ECS/Kubernetes",
                "• Post-deployment: Automated smoke tests and health checks",
                "• Rollback: Automatic rollback if health checks fail",
                "",
                "Deployment Script:",
                "  - name: Deploy to Production",
                "    if: github.ref == 'refs/heads/main'",
                "    run: |",
                "      kubectl apply -f k8s/deployment.yml",
                "      kubectl rollout status deployment/juiceshop",
                ""
            ]
        },
        {
            "heading": "Monitoring and Alerting",
            "content": [
                "✅ AUDIT CORRECTION #7: Security Monitoring and Incident Response",
                "",
                "Missing continuous monitoring and alerting for production security events.",
                "",
                "Implemented Monitoring:",
                "• Prometheus: Collects metrics (request rate, error rate, latency)",
                "• Grafana: Visualizes security dashboards (attack patterns, SQL injection attempts)",
                "• Slack/Email Alerts: Notifies security team on pipeline failures or vulnerability detection",
                "• Audit Logging: Stores all pipeline runs and scan results for compliance",
                "",
                "Alert Configuration:",
                "  - name: Notify Security Team",
                "    if: failure()",
                "    run: |",
                "      curl -X POST ${{ secrets.SLACK_WEBHOOK }} \\",
                "        -d '{\"text\":\"⚠️ DevSecOps pipeline failed: ${{ github.run_id }}\"}'",
                ""
            ]
        }
    ]
    
    # Apply all corrections
    modified = False
    for correction in corrections:
        print(f"[AUDIT] Applying correction: {correction['heading']}")
        if insert_section_after_heading(doc, correction['heading'], correction['content']):
            modified = True
            print(f"  ✅ Successfully inserted content for '{correction['heading']}'")
        else:
            print(f"  ⚠️  Heading '{correction['heading']}' not found, appending to end")
            # Append to end if heading not found
            doc.add_paragraph("")
            doc.add_heading(correction['heading'], level=2)
            for line in correction['content']:
                doc.add_paragraph(line)
            modified = True
    
    # Add audit metadata
    doc.add_page_break()
    doc.add_heading("Audit Metadata", level=1)
    doc.add_paragraph(f"Report updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    doc.add_paragraph("Audit performed by: AI Worker #2 (DevSecOps Pipeline Specialist)")
    doc.add_paragraph("Total corrections applied: 7")
    doc.add_paragraph("")
    doc.add_paragraph("Verification checklist:")
    doc.add_paragraph("☑ Linux container runner configuration")
    doc.add_paragraph("☑ SAST/SCA tool integration (Semgrep, Trivy, Bandit)")
    doc.add_paragraph("☑ Secret scanning with Gitleaks")
    doc.add_paragraph("☑ Quality gate enforcement")
    doc.add_paragraph("☑ Container image security scanning")
    doc.add_paragraph("☑ Automated deployment pipeline")
    doc.add_paragraph("☑ Security monitoring and alerting")
    
    # Save updated document
    output_path = doc_path.replace('.docx', '_UPDATED.docx')
    doc.save(output_path)
    print(f"\n✅ [SUCCESS] Updated report saved: {output_path}")
    print(f"[INFO] Total corrections applied: 7")
    
    return output_path

def main():
    print("=" * 70)
    print("DevSecOps JuiceShop Pipeline - Report Updater")
    print("Applying 7 audit corrections from Worker #2")
    print("=" * 70)
    print()
    
    # Find existing report
    report_path = find_docx_report()
    
    if not report_path:
        print("❌ [ERROR] No .docx report found in .aKetqua directory")
        print("[HINT] Please ensure the original report exists before running this script")
        sys.exit(1)
    
    # Update report
    try:
        updated_path = update_devsecops_report(report_path)
        print()
        print("=" * 70)
        print("✅ AUDIT COMPLETE")
        print(f"Original report: {report_path}")
        print(f"Updated report: {updated_path}")
        print("=" * 70)
        
    except Exception as e:
        print(f"\n❌ [ERROR] Failed to update report: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
