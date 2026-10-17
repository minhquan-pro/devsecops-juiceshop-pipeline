#!/usr/bin/env python3
import zipfile, re, sys

sys.stdout.reconfigure(encoding='utf-8')

def extract_text(docx_path):
    with zipfile.ZipFile(docx_path) as z:
        xml = z.read('word/document.xml').decode('utf-8')
    text = re.sub(r'<[^>]+>', ' ', xml)
    return ' '.join(text.split())

t1 = extract_text('.aKetqua/Bao_Cao_Bai_Tap_Lon_window_linux_Juice_Shop.docx')
t2 = extract_text('.aKetqua/Bao_Cao_Bai_Tap_Lon_window_linux_Juice_Shop_UPDATED.docx')

print(f"Original word count: {len(t1.split())}, char count: {len(t1)}")
print(f"UPDATED word count: {len(t2.split())}, char count: {len(t2)}")
print(f"Diff words: {len(t2.split()) - len(t1.split())}")

# Check what was added in update_report_devsecops.py
# The script added 7 sections:
# 1. Pipeline Runner Matrix
# 2. Modern SAST/SCA Toolchain
# 3. Dedicated Secret Detection Gate
# 4. Binary Scan Gate
# 5. Container Security Scanning
# 6. Automated Deployment & Rollback Strategy
# 7. Runtime Monitoring & Alerting

sections = [
    "Pipeline Runner Matrix",
    "Modern SAST/SCA Toolchain",
    "Dedicated Secret Detection Gate",
    "Binary Scan Gate",
    "Container Security Scanning",
    "Automated Deployment & Rollback Strategy",
    "Runtime Monitoring & Alerting",
    "kubectl",
    "Prometheus",
    "Grafana",
    "AWS ECS",
    "gen_report_appendices.py"
]

for s in sections:
    c1 = t1.count(s)
    c2 = t2.count(s)
    print(f"'{s}': in Original = {c1}, in UPDATED = {c2}")

print("\n--- Occurrences of gen_report_appendices in Original ---")
for m in re.finditer(r'gen_report_appendices', t1):
    print("Match:", t1[max(0, m.start()-150):min(len(t1), m.end()+150)])
    print("-" * 50)

print("\n--- Extract Headings / Table of Contents in Original ---")
with zipfile.ZipFile('.aKetqua/Bao_Cao_Bai_Tap_Lon_window_linux_Juice_Shop.docx') as z:
    xml = z.read('word/document.xml').decode('utf-8')

# Find paragraph elements with headings or text starting with CHƯƠNG, PHỤ LỤC, etc.
paras = re.findall(r'<w:p[ >].*?</w:p>', xml)
headings = []
for p in paras:
    p_text = ' '.join(re.sub(r'<[^>]+>', ' ', p).split())
    if re.match(r'^(CHƯƠNG\s+\d+|PHỤ\s+LỤC\s+[A-Z]|MỤC\s+LỤC|LỜI\s+CẢM\s+ƠN|LỜI\s+CAM\s+ĐOAN|\d+\.\d+(\.\d+)?\s+[A-ZÀ-Ỹ])', p_text):
        if len(p_text) < 120:
            headings.append(p_text)

print(f"Total matching structural headings found: {len(headings)}")
for h in headings[:35]:
    print(" -", h)
if len(headings) > 35:
    print(f" ... and {len(headings)-35} more headings")
    print("Last 10 headings:")
    for h in headings[-10:]:
        print(" -", h)

print("\n--- CHAPTER 9 ALL SCENARIOS ---")
c9 = t1.find('CHƯƠNG 9:')
c10 = t1.find('CHƯƠNG 10:')
if c9 != -1:
    ch9_text = t1[c9:c10]
    scenarios = re.findall(r'(9\.\d+\s+Kịch bản \d+:[^\n.]+)', ch9_text)
    for sc in scenarios:
        print("Sc:", sc)

print("\n--- CHAPTER 10 ALL AUDITS ---")
if c10 != -1:
    p_a = t1.find('PHỤ LỤC A:')
    ch10_text = t1[c10:p_a] if p_a != -1 else t1[c10:c10+20000]
    audits = re.findall(r'(KIỂM TOÁN MÃ NGUỒN CHUYÊN SÂU:[^\n.]+)', ch10_text)
    for a in audits:
        print("Audit:", a)

print("\n--- CHAPTER 10 OVERVIEW ---")
if c10 != -1:
    p_a = t1.find('PHỤ LỤC A:')
    end10 = p_a if p_a != -1 else c10 + 3000
    print(t1[c10:end10][:2500])
