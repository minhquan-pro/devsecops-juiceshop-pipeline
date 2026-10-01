"""
Server: JuiceSec Analyzer Web Server
Đề tài: Nghiên cứu các lỗ hổng bảo mật Web theo PortSwigger Web Security
và xây dựng ứng dụng phân tích lỗ hổng trên nền tảng OWASP Juice Shop.
Khoa An toàn Thông tin - Học viện Công nghệ Bưu chính Viễn thông.
"""

import os
import sys
from flask import Flask, render_template, request, jsonify, send_file
from knowledge_base import get_all_vulnerabilities, get_vulnerability_by_id
from vuln_analyzer import JuiceShopAnalyzer, get_code_audit_data

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)

app = Flask(__name__, template_folder=os.path.join(BASE_DIR, 'templates'))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/knowledge-base', methods=['GET'])
def api_knowledge_base():
    vuln_id = request.args.get('id')
    if vuln_id:
        v = get_vulnerability_by_id(vuln_id)
        if v:
            return jsonify(v)
        return jsonify({"error": "Không tìm thấy lỗ hổng"}), 404
    return jsonify(get_all_vulnerabilities())

@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.get_json() or {}
    target_url = data.get('target_url', 'http://localhost:3000').strip()
    mode = data.get('mode', 'live')

    analyzer = JuiceShopAnalyzer(target_url=target_url)
    if mode == 'simulation':
        results = analyzer.run_simulated_scan(reason="Người dùng yêu cầu chế độ mô phỏng trắc địa thực tế của OWASP Juice Shop.")
    else:
        results = analyzer.run_live_scan()
    return jsonify(results)

@app.route('/api/code-audit', methods=['GET'])
def api_code_audit():
    return jsonify(get_code_audit_data())

@app.route('/api/download-word', methods=['GET'])
def download_word():
    word_file = os.path.join(PROJECT_ROOT, "Bao_Cao_Bai_Tap_Lon_ATTT_Juice_Shop.docx")
    if os.path.exists(word_file):
        return send_file(word_file, as_attachment=True, download_name="Bao_Cao_Bai_Tap_Lon_ATTT_Juice_Shop.docx")
    return jsonify({"error": "Chưa tìm thấy file Báo cáo Word. Vui lòng tạo báo cáo trước."}), 404

@app.route('/api/download-md', methods=['GET'])
def download_md():
    md_file = os.path.join(PROJECT_ROOT, "BAO_CAO_BTL_ATTT_JUICE_SHOP.md")
    if os.path.exists(md_file):
        return send_file(md_file, as_attachment=True, download_name="BAO_CAO_BTL_ATTT_JUICE_SHOP.md")
    return jsonify({"error": "Chưa tìm thấy file Báo cáo Markdown."}), 404

def run_server(port=5000):
    print("=" * 60)
    print("  JUICESEC ANALYZER - OWASP JUICE SHOP VULNERABILITY ANALYZER")
    print("  PTIT - Faculty of Information Security")
    print(f"  Server running at: http://127.0.0.1:{port}")
    print("=" * 60)
    app.run(host='127.0.0.1', port=port, debug=False)

if __name__ == '__main__':
    port = 5000
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass
    run_server(port)
