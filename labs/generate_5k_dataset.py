#!/usr/bin/env python3
"""
labs/generate_5k_dataset.py
------------------------------------------------------------------------------
Trình sinh tập dữ liệu 5.000 mẫu mã nguồn đối ngẫu (Contrastive Pairs).
- 2.500 mẫu vulnerable (label=1)
- 2.500 mẫu benign/remediated (label=0)
- 10 Danh mục CWE x 250 cặp = 2.500 cặp (5.000 snippet)
- 6 Framework/Ngữ cảnh: Flask, Django, Raw Python, Express.js, Fastify, Node.js http core
- Chung group_id giữa mỗi cặp đối ngẫu phục vụ StratifiedGroupKFold
- Xác thực cú pháp Python 100% bằng ast.parse
- Xuất dữ liệu chuẩn định dạng: data/augmented_5000.json
------------------------------------------------------------------------------
"""

import ast
import json
import os
import sys
import time

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
from pathlib import Path
from typing import Dict, List, Tuple

# Danh sách 10 CWE theo đặc tả
CWE_LIST = [
    "CWE-89",    # SQL Injection
    "CWE-78",    # Command Injection
    "CWE-22",    # Path Traversal
    "CWE-79",    # Cross-Site Scripting (XSS)
    "CWE-502",   # Insecure Deserialization
    "CWE-94",    # Eval / Code Injection
    "CWE-918",   # Server-Side Request Forgery (SSRF)
    "CWE-347",   # JWT algorithm: none / improper verification
    "CWE-1321",  # Prototype Pollution
    "CWE-611",   # XML External Entity (XXE)
]

# 6 Framework / Ngữ cảnh phân bổ
FRAMEWORKS = [
    "Flask",
    "Django",
    "Raw Python",
    "Express.js",
    "Fastify",
    "Node.js http core",
]

PYTHON_FRAMEWORKS = {"Flask", "Django", "Raw Python"}

# Pool định danh phong phú để biến thể hóa mã nguồn
ROUTES = [
    "/api/v1/resource", "/api/v2/items", "/service/fetch", "/internal/lookup",
    "/portal/search", "/admin/audit", "/users/profile", "/system/query",
    "/gateway/dispatch", "/catalog/filter", "/billing/invoice", "/data/export",
    "/auth/verify", "/proxy/relay", "/media/view", "/report/generate"
]

FN_NAMES = [
    "handle_request", "query_records", "fetch_data", "process_input",
    "lookup_entity", "search_inventory", "render_view", "dispatch_task",
    "sync_account", "validate_and_run", "load_profile", "read_document",
    "export_metrics", "eval_formula", "parse_payload", "resolve_target"
]

TABLES = [
    "users", "accounts", "customers", "orders", "invoices", "audit_logs",
    "transactions", "vouchers", "products", "credentials", "shipments", "profiles"
]

COLS = [
    "id", "uuid", "username", "email", "account_key", "tenant_id",
    "status", "auth_token", "document_id", "slug", "role_type", "reference"
]

VAR_NAMES = [
    "user_id", "filter_val", "query_param", "token_str", "target_key",
    "item_code", "lookup_val", "arg_token", "payload_val", "tenant_str"
]

PARAM_NAMES = [
    "id", "q", "token", "key", "ref", "query", "user", "file", "target", "expr"
]

CMD_TOOLS = [
    "ping", "traceroute", "nslookup", "whois", "dig", "uptime", "curl"
]


# ==============================================================================
# HỆ THỐNG TEMPLATE GENERATOR CHO 10 CWE VÀ 6 FRAMEWORK
# ==============================================================================

def gen_cwe89(fw: str, var_idx: int) -> Tuple[str, str]:
    """CWE-89: SQL Injection"""
    rt = ROUTES[var_idx % len(ROUTES)] + f"_{var_idx}"
    fn = f"{FN_NAMES[var_idx % len(FN_NAMES)]}_{var_idx}"
    tbl = TABLES[var_idx % len(TABLES)]
    col = COLS[var_idx % len(COLS)]
    var = f"{VAR_NAMES[var_idx % len(VAR_NAMES)]}_{var_idx}"
    prm = PARAM_NAMES[var_idx % len(PARAM_NAMES)]

    if fw == "Flask":
        vuln = (
            f"from flask import Flask, request, jsonify\n"
            f"import sqlite3\n\n"
            f"app = Flask(__name__)\n\n"
            f"@app.route('{rt}', methods=['GET'])\n"
            f"def {fn}():\n"
            f"    {var} = request.args.get('{prm}', '')\n"
            f"    conn = sqlite3.connect('database.db')\n"
            f"    cursor = conn.cursor()\n"
            f"    query = f\"SELECT * FROM {tbl} WHERE {col} = '{{{var}}}'\"\n"
            f"    cursor.execute(query)\n"
            f"    rows = cursor.fetchall()\n"
            f"    conn.close()\n"
            f"    return jsonify(rows)\n"
        )
        safe = (
            f"from flask import Flask, request, jsonify\n"
            f"import sqlite3\n\n"
            f"app = Flask(__name__)\n\n"
            f"@app.route('{rt}', methods=['GET'])\n"
            f"def {fn}():\n"
            f"    {var} = request.args.get('{prm}', '')\n"
            f"    conn = sqlite3.connect('database.db')\n"
            f"    cursor = conn.cursor()\n"
            f"    query = \"SELECT * FROM {tbl} WHERE {col} = ?\"\n"
            f"    cursor.execute(query, ({var},))\n"
            f"    rows = cursor.fetchall()\n"
            f"    conn.close()\n"
            f"    return jsonify(rows)\n"
        )
    elif fw == "Django":
        vuln = (
            f"from django.http import JsonResponse\n"
            f"from django.db import connection\n\n"
            f"def {fn}(request):\n"
            f"    {var} = request.GET.get('{prm}', '')\n"
            f"    with connection.cursor() as cursor:\n"
            f"        cursor.execute(f\"SELECT * FROM {tbl} WHERE {col} = '{{{var}}}'\")\n"
            f"        records = cursor.fetchall()\n"
            f"    return JsonResponse({{'results': records}})\n"
        )
        safe = (
            f"from django.http import JsonResponse\n"
            f"from django.db import connection\n\n"
            f"def {fn}(request):\n"
            f"    {var} = request.GET.get('{prm}', '')\n"
            f"    with connection.cursor() as cursor:\n"
            f"        cursor.execute(\"SELECT * FROM {tbl} WHERE {col} = %s\", [{var}])\n"
            f"        records = cursor.fetchall()\n"
            f"    return JsonResponse({{'results': records}})\n"
        )
    elif fw == "Raw Python":
        vuln = (
            f"import sqlite3\n\n"
            f"def {fn}({var}):\n"
            f"    conn = sqlite3.connect('warehouse.db')\n"
            f"    cursor = conn.cursor()\n"
            f"    raw_sql = f\"SELECT {col} FROM {tbl} WHERE id = '{{{var}}}'\"\n"
            f"    cursor.execute(raw_sql)\n"
            f"    data = cursor.fetchone()\n"
            f"    conn.close()\n"
            f"    return data\n"
        )
        safe = (
            f"import sqlite3\n\n"
            f"def {fn}({var}):\n"
            f"    conn = sqlite3.connect('warehouse.db')\n"
            f"    cursor = conn.cursor()\n"
            f"    safe_sql = \"SELECT {col} FROM {tbl} WHERE id = ?\"\n"
            f"    cursor.execute(safe_sql, ({var},))\n"
            f"    data = cursor.fetchone()\n"
            f"    conn.close()\n"
            f"    return data\n"
        )
    elif fw == "Express.js":
        vuln = (
            f"const express = require('express');\n"
            f"const {{ Client }} = require('pg');\n"
            f"const app = express();\n\n"
            f"app.get('{rt}', async (req, res) => {{\n"
            f"    const {var} = req.query.{prm};\n"
            f"    const client = new Client();\n"
            f"    await client.connect();\n"
            f"    const sql = `SELECT * FROM {tbl} WHERE {col} = '${{{var}}}'`;\n"
            f"    const result = await client.query(sql);\n"
            f"    await client.end();\n"
            f"    res.json(result.rows);\n"
            f"}});\n"
        )
        safe = (
            f"const express = require('express');\n"
            f"const {{ Client }} = require('pg');\n"
            f"const app = express();\n\n"
            f"app.get('{rt}', async (req, res) => {{\n"
            f"    const {var} = req.query.{prm};\n"
            f"    const client = new Client();\n"
            f"    await client.connect();\n"
            f"    const sql = 'SELECT * FROM {tbl} WHERE {col} = $1';\n"
            f"    const result = await client.query(sql, [{var}]);\n"
            f"    await client.end();\n"
            f"    res.json(result.rows);\n"
            f"}});\n"
        )
    elif fw == "Fastify":
        vuln = (
            f"const fastify = require('fastify')();\n\n"
            f"fastify.get('{rt}', async (request, reply) => {{\n"
            f"    const {var} = request.query.{prm};\n"
            f"    const query = `SELECT * FROM {tbl} WHERE {col} = '${{{var}}}'`;\n"
            f"    const rows = await fastify.pg.query(query);\n"
            f"    return rows.rows;\n"
            f"}});\n"
        )
        safe = (
            f"const fastify = require('fastify')();\n\n"
            f"fastify.get('{rt}', async (request, reply) => {{\n"
            f"    const {var} = request.query.{prm};\n"
            f"    const query = 'SELECT * FROM {tbl} WHERE {col} = $1';\n"
            f"    const rows = await fastify.pg.query(query, [{var}]);\n"
            f"    return rows.rows;\n"
            f"}});\n"
        )
    else:  # Node.js http core
        vuln = (
            f"const http = require('http');\n"
            f"const url = require('url');\n"
            f"const sqlite3 = require('sqlite3');\n"
            f"const db = new sqlite3.Database(':memory:');\n\n"
            f"http.createServer((req, res) => {{\n"
            f"    const parsed = url.parse(req.url, true);\n"
            f"    const {var} = parsed.query.{prm} || '';\n"
            f"    const sql = `SELECT * FROM {tbl} WHERE {col} = '${{{var}}}'`;\n"
            f"    db.all(sql, (err, rows) => {{\n"
            f"        res.writeHead(200, {{ 'Content-Type': 'application/json' }});\n"
            f"        res.end(JSON.stringify(rows || []));\n"
            f"    }});\n"
            f"}});\n"
        )
        safe = (
            f"const http = require('http');\n"
            f"const url = require('url');\n"
            f"const sqlite3 = require('sqlite3');\n"
            f"const db = new sqlite3.Database(':memory:');\n\n"
            f"http.createServer((req, res) => {{\n"
            f"    const parsed = url.parse(req.url, true);\n"
            f"    const {var} = parsed.query.{prm} || '';\n"
            f"    const sql = 'SELECT * FROM {tbl} WHERE {col} = ?';\n"
            f"    db.all(sql, [{var}], (err, rows) => {{\n"
            f"        res.writeHead(200, {{ 'Content-Type': 'application/json' }});\n"
            f"        res.end(JSON.stringify(rows || []));\n"
            f"    }});\n"
            f"}});\n"
        )
    return vuln, safe


def gen_cwe78(fw: str, var_idx: int) -> Tuple[str, str]:
    """CWE-78: Command Injection"""
    rt = ROUTES[var_idx % len(ROUTES)] + f"_{var_idx}"
    fn = f"{FN_NAMES[var_idx % len(FN_NAMES)]}_{var_idx}"
    var = f"{VAR_NAMES[var_idx % len(VAR_NAMES)]}_{var_idx}"
    prm = PARAM_NAMES[var_idx % len(PARAM_NAMES)]
    tool = CMD_TOOLS[var_idx % len(CMD_TOOLS)]

    if fw == "Flask":
        vuln = (
            f"import os\n"
            f"from flask import Flask, request\n\n"
            f"app = Flask(__name__)\n\n"
            f"@app.route('{rt}')\n"
            f"def {fn}():\n"
            f"    {var} = request.args.get('{prm}', '')\n"
            f"    cmd = f\"{tool} {{{var}}}\"\n"
            f"    output = os.popen(cmd).read()\n"
            f"    return output\n"
        )
        safe = (
            f"import subprocess\n"
            f"from flask import Flask, request\n\n"
            f"app = Flask(__name__)\n\n"
            f"@app.route('{rt}')\n"
            f"def {fn}():\n"
            f"    {var} = request.args.get('{prm}', '')\n"
            f"    res = subprocess.run(['{tool}', {var}], capture_output=True, text=True, shell=False)\n"
            f"    return res.stdout\n"
        )
    elif fw == "Django":
        vuln = (
            f"import os\n"
            f"from django.http import HttpResponse\n\n"
            f"def {fn}(request):\n"
            f"    {var} = request.GET.get('{prm}', '')\n"
            f"    status = os.system(f\"{tool} {{{var}}}\")\n"
            f"    return HttpResponse(f\"Execution code: {{status}}\")\n"
        )
        safe = (
            f"import subprocess\n"
            f"from django.http import HttpResponse\n\n"
            f"def {fn}(request):\n"
            f"    {var} = request.GET.get('{prm}', '')\n"
            f"    res = subprocess.run(['{tool}', {var}], capture_output=True, shell=False)\n"
            f"    return HttpResponse(f\"Execution code: {{res.returncode}}\")\n"
        )
    elif fw == "Raw Python":
        vuln = (
            f"import subprocess\n\n"
            f"def {fn}({var}):\n"
            f"    command_str = f\"{tool} {{{var}}}\"\n"
            f"    return subprocess.check_output(command_str, shell=True)\n"
        )
        safe = (
            f"import subprocess\n\n"
            f"def {fn}({var}):\n"
            f"    command_args = ['{tool}', {var}]\n"
            f"    return subprocess.check_output(command_args, shell=False)\n"
        )
    elif fw == "Express.js":
        vuln = (
            f"const express = require('express');\n"
            f"const {{ exec }} = require('child_process');\n"
            f"const app = express();\n\n"
            f"app.get('{rt}', (req, res) => {{\n"
            f"    const {var} = req.query.{prm};\n"
            f"    exec(`{tool} ${{{var}}}`, (err, stdout) => {{\n"
            f"        res.send(stdout);\n"
            f"    }});\n"
            f"}});\n"
        )
        safe = (
            f"const express = require('express');\n"
            f"const {{ execFile }} = require('child_process');\n"
            f"const app = express();\n\n"
            f"app.get('{rt}', (req, res) => {{\n"
            f"    const {var} = req.query.{prm};\n"
            f"    execFile('{tool}', [String({var} || '')], (err, stdout) => {{\n"
            f"        res.send(stdout);\n"
            f"    }});\n"
            f"}});\n"
        )
    elif fw == "Fastify":
        vuln = (
            f"const fastify = require('fastify')();\n"
            f"const cp = require('child_process');\n\n"
            f"fastify.get('{rt}', async (request, reply) => {{\n"
            f"    const {var} = request.query.{prm};\n"
            f"    return new Promise((resolve) => {{\n"
            f"        cp.exec(`{tool} ${{{var}}}`, (err, stdout) => resolve(stdout));\n"
            f"    }});\n"
            f"}});\n"
        )
        safe = (
            f"const fastify = require('fastify')();\n"
            f"const cp = require('child_process');\n\n"
            f"fastify.get('{rt}', async (request, reply) => {{\n"
            f"    const {var} = request.query.{prm};\n"
            f"    return new Promise((resolve) => {{\n"
            f"        cp.execFile('{tool}', [String({var} || '')], (err, stdout) => resolve(stdout));\n"
            f"    }});\n"
            f"}});\n"
        )
    else:  # Node.js http core
        vuln = (
            f"const http = require('http');\n"
            f"const url = require('url');\n"
            f"const {{ exec }} = require('child_process');\n\n"
            f"http.createServer((req, res) => {{\n"
            f"    const query = url.parse(req.url, true).query;\n"
            f"    exec(`{tool} ${{query.{prm}}}`, (err, out) => {{\n"
            f"        res.writeHead(200);\n"
            f"        res.end(out);\n"
            f"    }});\n"
            f"}});\n"
        )
        safe = (
            f"const http = require('http');\n"
            f"const url = require('url');\n"
            f"const {{ execFile }} = require('child_process');\n\n"
            f"http.createServer((req, res) => {{\n"
            f"    const query = url.parse(req.url, true).query;\n"
            f"    execFile('{tool}', [String(query.{prm} || '')], (err, out) => {{\n"
            f"        res.writeHead(200);\n"
            f"        res.end(out);\n"
            f"    }});\n"
            f"}});\n"
        )
    return vuln, safe


def gen_cwe22(fw: str, var_idx: int) -> Tuple[str, str]:
    """CWE-22: Path Traversal"""
    rt = ROUTES[var_idx % len(ROUTES)] + f"_{var_idx}"
    fn = f"{FN_NAMES[var_idx % len(FN_NAMES)]}_{var_idx}"
    var = f"{VAR_NAMES[var_idx % len(VAR_NAMES)]}_{var_idx}"
    prm = PARAM_NAMES[var_idx % len(PARAM_NAMES)]

    if fw == "Flask":
        vuln = (
            f"import os\n"
            f"from flask import Flask, request\n\n"
            f"app = Flask(__name__)\n"
            f"BASE_DIR = '/var/data/exports'\n\n"
            f"@app.route('{rt}')\n"
            f"def {fn}():\n"
            f"    {var} = request.args.get('{prm}', 'default.txt')\n"
            f"    filepath = os.path.join(BASE_DIR, {var})\n"
            f"    with open(filepath, 'r', encoding='utf-8') as f:\n"
            f"        return f.read()\n"
        )
        safe = (
            f"import os\n"
            f"from flask import Flask, request, abort\n"
            f"from werkzeug.utils import secure_filename\n\n"
            f"app = Flask(__name__)\n"
            f"BASE_DIR = os.path.abspath('/var/data/exports')\n\n"
            f"@app.route('{rt}')\n"
            f"def {fn}():\n"
            f"    {var} = request.args.get('{prm}', 'default.txt')\n"
            f"    safe_name = secure_filename({var})\n"
            f"    filepath = os.path.abspath(os.path.join(BASE_DIR, safe_name))\n"
            f"    if not filepath.startswith(BASE_DIR):\n"
            f"        abort(403)\n"
            f"    with open(filepath, 'r', encoding='utf-8') as f:\n"
            f"        return f.read()\n"
        )
    elif fw == "Django":
        vuln = (
            f"import os\n"
            f"from django.http import HttpResponse\n\n"
            f"STORAGE_ROOT = '/srv/media/files'\n\n"
            f"def {fn}(request):\n"
            f"    {var} = request.GET.get('{prm}', '')\n"
            f"    target = os.path.join(STORAGE_ROOT, {var})\n"
            f"    with open(target, 'rb') as f:\n"
            f"        return HttpResponse(f.read(), content_type='text/plain')\n"
        )
        safe = (
            f"from django.http import HttpResponse, Http404\n"
            f"from django.utils._os import safe_join\n\n"
            f"STORAGE_ROOT = '/srv/media/files'\n\n"
            f"def {fn}(request):\n"
            f"    {var} = request.GET.get('{prm}', '')\n"
            f"    try:\n"
            f"        target = safe_join(STORAGE_ROOT, {var})\n"
            f"        with open(target, 'rb') as f:\n"
            f"            return HttpResponse(f.read(), content_type='text/plain')\n"
            f"    except ValueError:\n"
            f"        raise Http404('Access outside safe directory prohibited')\n"
        )
    elif fw == "Raw Python":
        vuln = (
            f"import os\n\n"
            f"def {fn}({var}):\n"
            f"    root_path = '/app/storage/docs'\n"
            f"    target = os.path.join(root_path, {var})\n"
            f"    with open(target, 'r') as fh:\n"
            f"        return fh.read()\n"
        )
        safe = (
            f"import os\n\n"
            f"def {fn}({var}):\n"
            f"    root_path = os.path.abspath('/app/storage/docs')\n"
            f"    target = os.path.abspath(os.path.join(root_path, {var}))\n"
            f"    if not target.startswith(root_path):\n"
            f"        raise PermissionError('Path traversal detected')\n"
            f"    with open(target, 'r') as fh:\n"
            f"        return fh.read()\n"
        )
    elif fw == "Express.js":
        vuln = (
            f"const express = require('express');\n"
            f"const path = require('path');\n"
            f"const fs = require('fs');\n"
            f"const app = express();\n\n"
            f"app.get('{rt}', (req, res) => {{\n"
            f"    const {var} = req.query.{prm};\n"
            f"    const fileLoc = path.join(__dirname, 'public/docs', {var});\n"
            f"    res.send(fs.readFileSync(fileLoc, 'utf-8'));\n"
            f"}});\n"
        )
        safe = (
            f"const express = require('express');\n"
            f"const path = require('path');\n"
            f"const fs = require('fs');\n"
            f"const app = express();\n\n"
            f"app.get('{rt}', (req, res) => {{\n"
            f"    const {var} = req.query.{prm};\n"
            f"    const safeBase = path.resolve(__dirname, 'public/docs');\n"
            f"    const fileLoc = path.resolve(safeBase, path.basename(String({var} || '')));\n"
            f"    if (!fileLoc.startsWith(safeBase)) {{\n"
            f"        return res.status(403).send('Forbidden');\n"
            f"    }}\n"
            f"    res.send(fs.readFileSync(fileLoc, 'utf-8'));\n"
            f"}});\n"
        )
    elif fw == "Fastify":
        vuln = (
            f"const fastify = require('fastify')();\n"
            f"const fs = require('fs');\n"
            f"const path = require('path');\n\n"
            f"fastify.get('{rt}', async (request, reply) => {{\n"
            f"    const {var} = request.query.{prm};\n"
            f"    const fullPath = path.join('/var/static', {var});\n"
            f"    return fs.promises.readFile(fullPath, 'utf8');\n"
            f"}});\n"
        )
        safe = (
            f"const fastify = require('fastify')();\n"
            f"const fs = require('fs');\n"
            f"const path = require('path');\n\n"
            f"fastify.get('{rt}', async (request, reply) => {{\n"
            f"    const {var} = request.query.{prm};\n"
            f"    const root = path.resolve('/var/static');\n"
            f"    const fullPath = path.resolve(root, path.basename(String({var} || '')));\n"
            f"    if (!fullPath.startsWith(root)) {{\n"
            f"        return reply.code(403).send('Access denied');\n"
            f"    }}\n"
            f"    return fs.promises.readFile(fullPath, 'utf8');\n"
            f"}});\n"
        )
    else:  # Node.js http core
        vuln = (
            f"const http = require('http');\n"
            f"const url = require('url');\n"
            f"const fs = require('fs');\n"
            f"const path = require('path');\n\n"
            f"http.createServer((req, res) => {{\n"
            f"    const query = url.parse(req.url, true).query;\n"
            f"    const loc = path.join('/assets', query.{prm});\n"
            f"    fs.readFile(loc, (err, data) => res.end(data));\n"
            f"}});\n"
        )
        safe = (
            f"const http = require('http');\n"
            f"const url = require('url');\n"
            f"const fs = require('fs');\n"
            f"const path = require('path');\n\n"
            f"http.createServer((req, res) => {{\n"
            f"    const query = url.parse(req.url, true).query;\n"
            f"    const root = path.resolve('/assets');\n"
            f"    const loc = path.resolve(root, path.basename(query.{prm} || ''));\n"
            f"    if (!loc.startsWith(root)) {{\n"
            f"        res.writeHead(403);\n"
            f"        return res.end('Invalid Path');\n"
            f"    }}\n"
            f"    fs.readFile(loc, (err, data) => res.end(data));\n"
            f"}});\n"
        )
    return vuln, safe


def gen_cwe79(fw: str, var_idx: int) -> Tuple[str, str]:
    """CWE-79: Cross-Site Scripting (XSS)"""
    rt = ROUTES[var_idx % len(ROUTES)] + f"_{var_idx}"
    fn = f"{FN_NAMES[var_idx % len(FN_NAMES)]}_{var_idx}"
    var = f"{VAR_NAMES[var_idx % len(VAR_NAMES)]}_{var_idx}"
    prm = PARAM_NAMES[var_idx % len(PARAM_NAMES)]

    if fw == "Flask":
        vuln = (
            f"from flask import Flask, request, render_template_string\n\n"
            f"app = Flask(__name__)\n\n"
            f"@app.route('{rt}')\n"
            f"def {fn}():\n"
            f"    {var} = request.args.get('{prm}', '')\n"
            f"    template = f\"<div>Welcome, {{{var}}}!</div>\"\n"
            f"    return render_template_string(template)\n"
        )
        safe = (
            f"from flask import Flask, request, render_template_string\n\n"
            f"app = Flask(__name__)\n\n"
            f"@app.route('{rt}')\n"
            f"def {fn}():\n"
            f"    {var} = request.args.get('{prm}', '')\n"
            f"    template = \"<div>Welcome, {{ user_input }}!</div>\"\n"
            f"    return render_template_string(template, user_input={var})\n"
        )
    elif fw == "Django":
        vuln = (
            f"from django.http import HttpResponse\n"
            f"from django.utils.safestring import mark_safe\n\n"
            f"def {fn}(request):\n"
            f"    {var} = request.GET.get('{prm}', '')\n"
            f"    content = mark_safe(f\"<span class='badge'>{{{var}}}</span>\")\n"
            f"    return HttpResponse(content)\n"
        )
        safe = (
            f"from django.http import HttpResponse\n"
            f"from django.utils.html import escape\n\n"
            f"def {fn}(request):\n"
            f"    {var} = request.GET.get('{prm}', '')\n"
            f"    safe_text = escape({var})\n"
            f"    content = f\"<span class='badge'>{{safe_text}}</span>\"\n"
            f"    return HttpResponse(content)\n"
        )
    elif fw == "Raw Python":
        vuln = (
            f"def {fn}({var}):\n"
            f"    return f\"<html><body><h3>Results for: {{{var}}}</h3></body></html>\"\n"
        )
        safe = (
            f"import html\n\n"
            f"def {fn}({var}):\n"
            f"    clean_val = html.escape({var})\n"
            f"    return f\"<html><body><h3>Results for: {{clean_val}}</h3></body></html>\"\n"
        )
    elif fw == "Express.js":
        vuln = (
            f"const express = require('express');\n"
            f"const app = express();\n\n"
            f"app.get('{rt}', (req, res) => {{\n"
            f"    const {var} = req.query.{prm};\n"
            f"    res.send(`<h1>Greeting: ${{{var}}}</h1>`);\n"
            f"}});\n"
        )
        safe = (
            f"const express = require('express');\n"
            f"const escapeHtml = require('escape-html');\n"
            f"const app = express();\n\n"
            f"app.get('{rt}', (req, res) => {{\n"
            f"    const {var} = req.query.{prm};\n"
            f"    res.send(`<h1>Greeting: ${{escapeHtml({var} || '')}}</h1>`);\n"
            f"}});\n"
        )
    elif fw == "Fastify":
        vuln = (
            f"const fastify = require('fastify')();\n\n"
            f"fastify.get('{rt}', async (request, reply) => {{\n"
            f"    const {var} = request.query.{prm};\n"
            f"    reply.type('text/html');\n"
            f"    return `<div class=\"content\">${{{var}}}</div>`;\n"
            f"}});\n"
        )
        safe = (
            f"const fastify = require('fastify')();\n"
            f"const sanitizeHtml = require('sanitize-html');\n\n"
            f"fastify.get('{rt}', async (request, reply) => {{\n"
            f"    const {var} = request.query.{prm};\n"
            f"    reply.type('text/html');\n"
            f"    return `<div class=\"content\">${{sanitizeHtml({var} || '')}}</div>`;\n"
            f"}});\n"
        )
    else:  # Node.js http core
        vuln = (
            f"const http = require('http');\n"
            f"const url = require('url');\n\n"
            f"http.createServer((req, res) => {{\n"
            f"    const query = url.parse(req.url, true).query;\n"
            f"    res.writeHead(200, {{ 'Content-Type': 'text/html' }});\n"
            f"    res.end(`<div>Search item: ${{query.{prm}}}</div>`);\n"
            f"}});\n"
        )
        safe = (
            f"const http = require('http');\n"
            f"const url = require('url');\n"
            f"const validator = require('validator');\n\n"
            f"http.createServer((req, res) => {{\n"
            f"    const query = url.parse(req.url, true).query;\n"
            f"    res.writeHead(200, {{ 'Content-Type': 'text/html' }});\n"
            f"    res.end(`<div>Search item: ${{validator.escape(query.{prm} || '')}}</div>`);\n"
            f"}});\n"
        )
    return vuln, safe


def gen_cwe502(fw: str, var_idx: int) -> Tuple[str, str]:
    """CWE-502: Insecure Deserialization"""
    rt = ROUTES[var_idx % len(ROUTES)] + f"_{var_idx}"
    fn = f"{FN_NAMES[var_idx % len(FN_NAMES)]}_{var_idx}"
    var = f"{VAR_NAMES[var_idx % len(VAR_NAMES)]}_{var_idx}"
    prm = PARAM_NAMES[var_idx % len(PARAM_NAMES)]

    if fw == "Flask":
        vuln = (
            f"import pickle\n"
            f"import base64\n"
            f"from flask import Flask, request, jsonify\n\n"
            f"app = Flask(__name__)\n\n"
            f"@app.route('{rt}', methods=['POST'])\n"
            f"def {fn}():\n"
            f"    token = request.headers.get('{prm}')\n"
            f"    {var} = pickle.loads(base64.b64decode(token))\n"
            f"    return jsonify(status='processed')\n"
        )
        safe = (
            f"import json\n"
            f"import base64\n"
            f"from flask import Flask, request, jsonify\n\n"
            f"app = Flask(__name__)\n\n"
            f"@app.route('{rt}', methods=['POST'])\n"
            f"def {fn}():\n"
            f"    token = request.headers.get('{prm}')\n"
            f"    {var} = json.loads(base64.b64decode(token).decode('utf-8'))\n"
            f"    return jsonify(status='processed')\n"
        )
    elif fw == "Django":
        vuln = (
            f"import pickle\n"
            f"import base64\n"
            f"from django.http import HttpResponse\n\n"
            f"def {fn}(request):\n"
            f"    raw_data = request.COOKIES.get('{prm}')\n"
            f"    {var} = pickle.loads(base64.b64decode(raw_data))\n"
            f"    return HttpResponse('Session object restored')\n"
        )
        safe = (
            f"from django.core import signing\n"
            f"from django.http import HttpResponse\n\n"
            f"def {fn}(request):\n"
            f"    raw_data = request.COOKIES.get('{prm}')\n"
            f"    {var} = signing.loads(raw_data)\n"
            f"    return HttpResponse('Session object restored')\n"
        )
    elif fw == "Raw Python":
        vuln = (
            f"import yaml\n\n"
            f"def {fn}(raw_stream):\n"
            f"    {var} = yaml.load(raw_stream, Loader=yaml.Loader)\n"
            f"    return {var}\n"
        )
        safe = (
            f"import yaml\n\n"
            f"def {fn}(raw_stream):\n"
            f"    {var} = yaml.safe_load(raw_stream)\n"
            f"    return {var}\n"
        )
    elif fw == "Express.js":
        vuln = (
            f"const express = require('express');\n"
            f"const serialize = require('node-serialize');\n"
            f"const app = express();\n\n"
            f"app.post('{rt}', (req, res) => {{\n"
            f"    const token = req.headers['{prm}'];\n"
            f"    const {var} = serialize.unserialize(Buffer.from(token, 'base64').toString());\n"
            f"    res.json({{ status: 'success' }});\n"
            f"}});\n"
        )
        safe = (
            f"const express = require('express');\n"
            f"const app = express();\n\n"
            f"app.post('{rt}', (req, res) => {{\n"
            f"    const token = req.headers['{prm}'];\n"
            f"    const {var} = JSON.parse(Buffer.from(token, 'base64').toString());\n"
            f"    res.json({{ status: 'success' }});\n"
            f"}});\n"
        )
    elif fw == "Fastify":
        vuln = (
            f"const fastify = require('fastify')();\n"
            f"const serialize = require('node-serialize');\n\n"
            f"fastify.post('{rt}', async (request, reply) => {{\n"
            f"    const payload = request.body.{prm};\n"
            f"    const {var} = serialize.unserialize(payload);\n"
            f"    return {{ loaded: true }};\n"
            f"}});\n"
        )
        safe = (
            f"const fastify = require('fastify')();\n\n"
            f"fastify.post('{rt}', async (request, reply) => {{\n"
            f"    const payload = request.body.{prm};\n"
            f"    const {var} = JSON.parse(payload);\n"
            f"    return {{ loaded: true }};\n"
            f"}});\n"
        )
    else:  # Node.js http core
        vuln = (
            f"const http = require('http');\n"
            f"const funcster = require('funcster');\n\n"
            f"http.createServer((req, res) => {{\n"
            f"    let body = '';\n"
            f"    req.on('data', c => body += c);\n"
            f"    req.on('end', () => {{\n"
            f"        const {var} = funcster.deserialize(body);\n"
            f"        res.end('deserialized');\n"
            f"    }});\n"
            f"}});\n"
        )
        safe = (
            f"const http = require('http');\n\n"
            f"http.createServer((req, res) => {{\n"
            f"    let body = '';\n"
            f"    req.on('data', c => body += c);\n"
            f"    req.on('end', () => {{\n"
            f"        const {var} = JSON.parse(body);\n"
            f"        res.end('deserialized');\n"
            f"    }});\n"
            f"}});\n"
        )
    return vuln, safe


def gen_cwe94(fw: str, var_idx: int) -> Tuple[str, str]:
    """CWE-94: Eval / Code Injection"""
    rt = ROUTES[var_idx % len(ROUTES)] + f"_{var_idx}"
    fn = f"{FN_NAMES[var_idx % len(FN_NAMES)]}_{var_idx}"
    var = f"{VAR_NAMES[var_idx % len(VAR_NAMES)]}_{var_idx}"
    prm = PARAM_NAMES[var_idx % len(PARAM_NAMES)]

    if fw == "Flask":
        vuln = (
            f"from flask import Flask, request, jsonify\n\n"
            f"app = Flask(__name__)\n\n"
            f"@app.route('{rt}')\n"
            f"def {fn}():\n"
            f"    {var} = request.args.get('{prm}', '0')\n"
            f"    calculated = eval({var})\n"
            f"    return jsonify(value=calculated)\n"
        )
        safe = (
            f"import ast\n"
            f"from flask import Flask, request, jsonify\n\n"
            f"app = Flask(__name__)\n\n"
            f"@app.route('{rt}')\n"
            f"def {fn}():\n"
            f"    {var} = request.args.get('{prm}', '0')\n"
            f"    calculated = ast.literal_eval({var})\n"
            f"    return jsonify(value=calculated)\n"
        )
    elif fw == "Django":
        vuln = (
            f"from django.http import HttpResponse\n\n"
            f"def {fn}(request):\n"
            f"    {var} = request.GET.get('{prm}', '1+1')\n"
            f"    scope = {{}}\n"
            f"    exec(f\"result = {{{var}}}\", scope)\n"
            f"    return HttpResponse(str(scope.get('result')))\n"
        )
        safe = (
            f"import operator\n"
            f"from django.http import HttpResponse\n\n"
            f"def {fn}(request):\n"
            f"    {var} = request.GET.get('{prm}', '1+1')\n"
            f"    ops = {{'+': operator.add, '-': operator.sub, '*': operator.mul}}\n"
            f"    tokens = {var}.split()\n"
            f"    if len(tokens) == 3 and tokens[1] in ops and tokens[0].isdigit() and tokens[2].isdigit():\n"
            f"        res = ops[tokens[1]](int(tokens[0]), int(tokens[2]))\n"
            f"    else:\n"
            f"        res = 0\n"
            f"    return HttpResponse(str(res))\n"
        )
    elif fw == "Raw Python":
        vuln = (
            f"def {fn}({var}):\n"
            f"    env = {{'__builtins__': __builtins__}}\n"
            f"    return eval({var}, env)\n"
        )
        safe = (
            f"import ast\n\n"
            f"def {fn}({var}):\n"
            f"    tree = ast.parse({var}, mode='eval')\n"
            f"    for node in ast.walk(tree):\n"
            f"        if not isinstance(node, (ast.Expression, ast.BinOp, ast.UnaryOp, ast.Constant, ast.Add, ast.Sub)):\n"
            f"            raise ValueError('Unsafe syntax expression')\n"
            f"    return eval(compile(tree, '<safe_calc>', 'eval'), {{'__builtins__': {{}}}})\n"
        )
    elif fw == "Express.js":
        vuln = (
            f"const express = require('express');\n"
            f"const app = express();\n"
            f"app.use(express.json());\n\n"
            f"app.post('{rt}', (req, res) => {{\n"
            f"    const {var} = req.body.{prm};\n"
            f"    const outcome = eval({var});\n"
            f"    res.json({{ outcome }});\n"
            f"}});\n"
        )
        safe = (
            f"const express = require('express');\n"
            f"const app = express();\n"
            f"app.use(express.json());\n\n"
            f"app.post('{rt}', (req, res) => {{\n"
            f"    const {var} = req.body.{prm};\n"
            f"    const num = Number({var});\n"
            f"    if (isNaN(num)) {{\n"
            f"        return res.status(400).json({{ error: 'Invalid numerical expression' }});\n"
            f"    }}\n"
            f"    res.json({{ outcome: num }});\n"
            f"}});\n"
        )
    elif fw == "Fastify":
        vuln = (
            f"const fastify = require('fastify')();\n\n"
            f"fastify.get('{rt}', async (request, reply) => {{\n"
            f"    const {var} = request.query.{prm};\n"
            f"    const fnEval = new Function('return ' + {var});\n"
            f"    return {{ result: fnEval() }};\n"
            f"}});\n"
        )
        safe = (
            f"const fastify = require('fastify')();\n\n"
            f"fastify.get('{rt}', async (request, reply) => {{\n"
            f"    const num = parseFloat(request.query.{prm});\n"
            f"    return {{ result: isNaN(num) ? 0 : num }};\n"
            f"}});\n"
        )
    else:  # Node.js http core
        vuln = (
            f"const http = require('http');\n"
            f"const vm = require('vm');\n"
            f"const url = require('url');\n\n"
            f"http.createServer((req, res) => {{\n"
            f"    const query = url.parse(req.url, true).query;\n"
            f"    const script = query.{prm} || '0';\n"
            f"    const calculated = vm.runInThisContext(script);\n"
            f"    res.end(String(calculated));\n"
            f"}});\n"
        )
        safe = (
            f"const http = require('http');\n"
            f"const url = require('url');\n\n"
            f"http.createServer((req, res) => {{\n"
            f"    const query = url.parse(req.url, true).query;\n"
            f"    const safeNum = Math.floor(Number(query.{prm})) || 0;\n"
            f"    res.end(String(safeNum));\n"
            f"}});\n"
        )
    return vuln, safe


def gen_cwe918(fw: str, var_idx: int) -> Tuple[str, str]:
    """CWE-918: Server-Side Request Forgery (SSRF)"""
    rt = ROUTES[var_idx % len(ROUTES)] + f"_{var_idx}"
    fn = f"{FN_NAMES[var_idx % len(FN_NAMES)]}_{var_idx}"
    var = f"{VAR_NAMES[var_idx % len(VAR_NAMES)]}_{var_idx}"
    prm = PARAM_NAMES[var_idx % len(PARAM_NAMES)]

    if fw == "Flask":
        vuln = (
            f"import requests\n"
            f"from flask import Flask, request, jsonify\n\n"
            f"app = Flask(__name__)\n\n"
            f"@app.route('{rt}')\n"
            f"def {fn}():\n"
            f"    {var} = request.args.get('{prm}')\n"
            f"    resp = requests.get({var}, timeout=5)\n"
            f"    return jsonify(status=resp.status_code, body=resp.text[:50])\n"
        )
        safe = (
            f"import requests\n"
            f"from urllib.parse import urlparse\n"
            f"from flask import Flask, request, abort, jsonify\n\n"
            f"app = Flask(__name__)\n"
            f"ALLOWED_DOMAINS = ['api.internal-partner.com', 'services.partner.org']\n\n"
            f"@app.route('{rt}')\n"
            f"def {fn}():\n"
            f"    {var} = request.args.get('{prm}')\n"
            f"    parsed = urlparse({var})\n"
            f"    if parsed.hostname not in ALLOWED_DOMAINS or parsed.scheme != 'https':\n"
            f"        abort(400)\n"
            f"    resp = requests.get({var}, timeout=5)\n"
            f"    return jsonify(status=resp.status_code, body=resp.text[:50])\n"
        )
    elif fw == "Django":
        vuln = (
            f"import urllib.request\n"
            f"from django.http import HttpResponse\n\n"
            f"def {fn}(request):\n"
            f"    {var} = request.GET.get('{prm}')\n"
            f"    stream = urllib.request.urlopen({var})\n"
            f"    return HttpResponse(stream.read())\n"
        )
        safe = (
            f"import urllib.request\n"
            f"from urllib.parse import urlparse\n"
            f"import ipaddress\n"
            f"import socket\n"
            f"from django.http import HttpResponse, HttpResponseBadRequest\n\n"
            f"def {fn}(request):\n"
            f"    {var} = request.GET.get('{prm}')\n"
            f"    host = urlparse({var}).hostname\n"
            f"    ip = ipaddress.ip_address(socket.gethostbyname(host))\n"
            f"    if ip.is_private or ip.is_loopback:\n"
            f"        return HttpResponseBadRequest('Access to private RFC1918 range blocked')\n"
            f"    stream = urllib.request.urlopen({var})\n"
            f"    return HttpResponse(stream.read())\n"
        )
    elif fw == "Raw Python":
        vuln = (
            f"import httpx\n\n"
            f"def {fn}({var}):\n"
            f"    client = httpx.Client()\n"
            f"    response = client.get({var})\n"
            f"    return response.json()\n"
        )
        safe = (
            f"import httpx\n"
            f"from urllib.parse import urlparse\n\n"
            f"APPROVED_HOSTS = {{'cdn.trusted-partner.net', 'api.external-feed.com'}}\n\n"
            f"def {fn}({var}):\n"
            f"    parsed = urlparse({var})\n"
            f"    if parsed.scheme != 'https' or parsed.hostname not in APPROVED_HOSTS:\n"
            f"        raise ValueError('Target host is outside approved white-list')\n"
            f"    client = httpx.Client()\n"
            f"    response = client.get({var})\n"
            f"    return response.json()\n"
        )
    elif fw == "Express.js":
        vuln = (
            f"const express = require('express');\n"
            f"const axios = require('axios');\n"
            f"const app = express();\n\n"
            f"app.get('{rt}', async (req, res) => {{\n"
            f"    const {var} = req.query.{prm};\n"
            f"    const outcome = await axios.get({var});\n"
            f"    res.send(outcome.data);\n"
            f"}});\n"
        )
        safe = (
            f"const express = require('express');\n"
            f"const axios = require('axios');\n"
            f"const {{ URL }} = require('url');\n"
            f"const app = express();\n\n"
            f"const ALLOWED_HOSTS = ['trusted.cdn.com', 'api.public-feed.org'];\n\n"
            f"app.get('{rt}', async (req, res) => {{\n"
            f"    try {{\n"
            f"        const destUrl = new URL(req.query.{prm});\n"
            f"        if (destUrl.protocol !== 'https:' || !ALLOWED_HOSTS.includes(destUrl.hostname)) {{\n"
            f"            return res.status(403).send('Target destination forbidden');\n"
            f"        }}\n"
            f"        const outcome = await axios.get(destUrl.href);\n"
            f"        res.send(outcome.data);\n"
            f"}});\n"
        )
    elif fw == "Fastify":
        vuln = (
            f"const fastify = require('fastify')();\n"
            f"const {{ request: undiciRequest }} = require('undici');\n\n"
            f"fastify.post('{rt}', async (request, reply) => {{\n"
            f"    const {var} = request.body.{prm};\n"
            f"    const {{ statusCode }} = await undiciRequest({var});\n"
            f"    return {{ statusCode }};\n"
            f"}});\n"
        )
        safe = (
            f"const fastify = require('fastify')();\n"
            f"const {{ request: undiciRequest }} = require('undici');\n"
            f"const {{ URL }} = require('url');\n\n"
            f"fastify.post('{rt}', async (request, reply) => {{\n"
            f"    const {var} = request.body.{prm};\n"
            f"    const parsed = new URL({var});\n"
            f"    if (parsed.protocol !== 'https:' || !parsed.hostname.endsWith('.secure-partner.com')) {{\n"
            f"        return reply.code(400).send({{ error: 'SSRF check triggered' }});\n"
            f"    }}\n"
            f"    const {{ statusCode }} = await undiciRequest(parsed.href);\n"
            f"    return {{ statusCode }};\n"
            f"}});\n"
        )
    else:  # Node.js http core
        vuln = (
            f"const http = require('http');\n"
            f"const url = require('url');\n\n"
            f"http.createServer((req, res) => {{\n"
            f"    const target = url.parse(req.url, true).query.{prm};\n"
            f"    http.get(target, (proxyRes) => proxyRes.pipe(res));\n"
            f"}});\n"
        )
        safe = (
            f"const http = require('http');\n"
            f"const url = require('url');\n"
            f"const WHITELIST = ['api.internal-mesh.local'];\n\n"
            f"http.createServer((req, res) => {{\n"
            f"    const target = url.parse(req.url, true).query.{prm} || '';\n"
            f"    const parsed = url.parse(target);\n"
            f"    if (!WHITELIST.includes(parsed.hostname)) {{\n"
            f"        res.writeHead(403);\n"
            f"        return res.end('Domain rejected');\n"
            f"    }}\n"
            f"    http.get(target, (proxyRes) => proxyRes.pipe(res));\n"
            f"}});\n"
        )
    return vuln, safe


def gen_cwe347(fw: str, var_idx: int) -> Tuple[str, str]:
    """CWE-347: Improper JWT Algorithm / Unverified Signature"""
    rt = ROUTES[var_idx % len(ROUTES)] + f"_{var_idx}"
    fn = f"{FN_NAMES[var_idx % len(FN_NAMES)]}_{var_idx}"
    var = f"{VAR_NAMES[var_idx % len(VAR_NAMES)]}_{var_idx}"

    if fw == "Flask":
        vuln = (
            f"import jwt\n"
            f"from flask import Flask, request, jsonify\n\n"
            f"app = Flask(__name__)\n\n"
            f"@app.route('{rt}')\n"
            f"def {fn}():\n"
            f"    auth_header = request.headers.get('Authorization', '')\n"
            f"    token = auth_header.replace('Bearer ', '')\n"
            f"    {var} = jwt.decode(token, options={{'verify_signature': False}})\n"
            f"    return jsonify({var})\n"
        )
        safe = (
            f"import jwt\n"
            f"from flask import Flask, request, jsonify\n\n"
            f"app = Flask(__name__)\n"
            f"SECRET_KEY = 'hardened-production-secret-key'\n\n"
            f"@app.route('{rt}')\n"
            f"def {fn}():\n"
            f"    auth_header = request.headers.get('Authorization', '')\n"
            f"    token = auth_header.replace('Bearer ', '')\n"
            f"    {var} = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])\n"
            f"    return jsonify({var})\n"
        )
    elif fw == "Django":
        vuln = (
            f"import jwt\n"
            f"from django.http import JsonResponse\n\n"
            f"def {fn}(request):\n"
            f"    token = request.META.get('HTTP_AUTHORIZATION', '').split(' ')[-1]\n"
            f"    {var} = jwt.decode(token, algorithms=['none', 'HS256'], options={{'verify_signature': False}})\n"
            f"    return JsonResponse({var})\n"
        )
        safe = (
            f"import jwt\n"
            f"from django.http import JsonResponse\n"
            f"from django.conf import settings\n\n"
            f"def {fn}(request):\n"
            f"    token = request.META.get('HTTP_AUTHORIZATION', '').split(' ')[-1]\n"
            f"    {var} = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])\n"
            f"    return JsonResponse({var})\n"
        )
    elif fw == "Raw Python":
        vuln = (
            f"import jwt\n\n"
            f"def {fn}(raw_jwt_token):\n"
            f"    {var} = jwt.decode(raw_jwt_token, key='', algorithms=['none'], options={{'verify_signature': False}})\n"
            f"    return {var}\n"
        )
        safe = (
            f"import jwt\n\n"
            f"PUB_KEY = '-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\\n-----END PUBLIC KEY-----'\n\n"
            f"def {fn}(raw_jwt_token):\n"
            f"    {var} = jwt.decode(raw_jwt_token, PUB_KEY, algorithms=['RS256'])\n"
            f"    return {var}\n"
        )
    elif fw == "Express.js":
        vuln = (
            f"const express = require('express');\n"
            f"const jwt = require('jsonwebtoken');\n"
            f"const app = express();\n\n"
            f"app.get('{rt}', (req, res) => {{\n"
            f"    const token = req.headers.authorization?.split(' ')[1];\n"
            f"    const {var} = jwt.verify(token, 'secret', {{ algorithms: ['none', 'HS256'] }});\n"
            f"    res.json({var});\n"
            f"}});\n"
        )
        safe = (
            f"const express = require('express');\n"
            f"const jwt = require('jsonwebtoken');\n"
            f"const app = express();\n\n"
            f"app.get('{rt}', (req, res) => {{\n"
            f"    const token = req.headers.authorization?.split(' ')[1];\n"
            f"    const {var} = jwt.verify(token, 'secret', {{ algorithms: ['HS256'] }});\n"
            f"    res.json({var});\n"
            f"}});\n"
        )
    elif fw == "Fastify":
        vuln = (
            f"const fastify = require('fastify')();\n"
            f"const jwt = require('jsonwebtoken');\n\n"
            f"fastify.get('{rt}', async (request, reply) => {{\n"
            f"    const token = request.headers['x-access-token'];\n"
            f"    const {var} = jwt.decode(token);\n"
            f"    return {{ user: {var}?.sub }};\n"
            f"}});\n"
        )
        safe = (
            f"const fastify = require('fastify')();\n"
            f"const jwt = require('jsonwebtoken');\n\n"
            f"fastify.get('{rt}', async (request, reply) => {{\n"
            f"    const token = request.headers['x-access-token'];\n"
            f"    const {var} = jwt.verify(token, process.env.JWT_SECRET, {{ algorithms: ['HS256'] }});\n"
            f"    return {{ user: {var}?.sub }};\n"
            f"}});\n"
        )
    else:  # Node.js http core
        vuln = (
            f"const http = require('http');\n"
            f"const jwt = require('jsonwebtoken');\n\n"
            f"http.createServer((req, res) => {{\n"
            f"    const auth = req.headers['authorization'] || '';\n"
            f"    const token = auth.replace('Bearer ', '');\n"
            f"    const {var} = jwt.verify(token, '', {{ algorithms: ['none'] }});\n"
            f"    res.end(JSON.stringify({var}));\n"
            f"}});\n"
        )
        safe = (
            f"const http = require('http');\n"
            f"const jwt = require('jsonwebtoken');\n\n"
            f"http.createServer((req, res) => {{\n"
            f"    const auth = req.headers['authorization'] || '';\n"
            f"    const token = auth.replace('Bearer ', '');\n"
            f"    const {var} = jwt.verify(token, process.env.PUB_KEY, {{ algorithms: ['RS256'] }});\n"
            f"    res.end(JSON.stringify({var}));\n"
            f"}});\n"
        )
    return vuln, safe


def gen_cwe1321(fw: str, var_idx: int) -> Tuple[str, str]:
    """CWE-1321: Prototype Pollution"""
    rt = ROUTES[var_idx % len(ROUTES)] + f"_{var_idx}"
    fn = f"{FN_NAMES[var_idx % len(FN_NAMES)]}_{var_idx}"

    if fw == "Flask":
        vuln = (
            f"from flask import Flask, request, jsonify\n\n"
            f"app = Flask(__name__)\n\n"
            f"class SessionState:\n"
            f"    pass\n\n"
            f"@app.route('{rt}', methods=['POST'])\n"
            f"def {fn}():\n"
            f"    data = request.get_json(force=True)\n"
            f"    inst = SessionState()\n"
            f"    for k, v in data.items():\n"
            f"        setattr(inst.__class__, k, v)\n"
            f"    return jsonify(status='updated')\n"
        )
        safe = (
            f"from flask import Flask, request, jsonify\n\n"
            f"app = Flask(__name__)\n\n"
            f"class SessionState:\n"
            f"    pass\n\n"
            f"BLOCKED_ATTRS = {{'__class__', '__base__', '__subclasses__', '__init__', '__globals__'}}\n\n"
            f"@app.route('{rt}', methods=['POST'])\n"
            f"def {fn}():\n"
            f"    data = request.get_json(force=True)\n"
            f"    inst = SessionState()\n"
            f"    for k, v in data.items():\n"
            f"        if k not in BLOCKED_ATTRS and not k.startswith('__'):\n"
            f"            setattr(inst, k, v)\n"
            f"    return jsonify(status='updated')\n"
        )
    elif fw == "Django":
        vuln = (
            f"import json\n"
            f"from django.http import JsonResponse\n\n"
            f"class UserPreferences:\n"
            f"    pass\n\n"
            f"def {fn}(request):\n"
            f"    data = json.loads(request.body)\n"
            f"    inst = UserPreferences()\n"
            f"    for key, val in data.items():\n"
            f"        setattr(inst.__class__, key, val)\n"
            f"    return JsonResponse({{'status': 'ok'}})\n"
        )
        safe = (
            f"import json\n"
            f"from django.http import JsonResponse\n\n"
            f"class UserPreferences:\n"
            f"    pass\n\n"
            f"RESTRICTED = {{'__class__', '__dict__', '__bases__', '__subclasses__'}}\n\n"
            f"def {fn}(request):\n"
            f"    data = json.loads(request.body)\n"
            f"    inst = UserPreferences()\n"
            f"    for key, val in data.items():\n"
            f"        if key not in RESTRICTED and not key.startswith('__'):\n"
            f"            setattr(inst, key, val)\n"
            f"    return JsonResponse({{'status': 'ok'}})\n"
        )
    elif fw == "Raw Python":
        vuln = (
            f"def {fn}(target_dict, source_dict):\n"
            f"    for k, v in source_dict.items():\n"
            f"        if isinstance(v, dict):\n"
            f"            target_dict.setdefault(k, {{}})\n"
            f"            {fn}(target_dict[k], v)\n"
            f"        else:\n"
            f"            target_dict[k] = v\n"
            f"    return target_dict\n"
        )
        safe = (
            f"def {fn}(target_dict, source_dict):\n"
            f"    for k, v in source_dict.items():\n"
            f"        if k in ('__class__', '__globals__', '__bases__', '__dict__'):\n"
            f"            continue\n"
            f"        if isinstance(v, dict):\n"
            f"            target_dict.setdefault(k, {{}})\n"
            f"            {fn}(target_dict[k], v)\n"
            f"        else:\n"
            f"            target_dict[k] = v\n"
            f"    return target_dict\n"
        )
    elif fw == "Express.js":
        vuln = (
            f"const express = require('express');\n"
            f"const app = express();\n"
            f"app.use(express.json());\n\n"
            f"function merge(dst, src) {{\n"
            f"    for (let key in src) {{\n"
            f"        if (typeof src[key] === 'object' && src[key] !== null) {{\n"
            f"            if (!dst[key]) dst[key] = {{}};\n"
            f"            merge(dst[key], src[key]);\n"
            f"        }} else {{\n"
            f"            dst[key] = src[key];\n"
            f"        }}\n"
            f"    }}\n"
            f"    return dst;\n"
            f"}}\n\n"
            f"app.post('{rt}', (req, res) => {{\n"
            f"    const base = {{}};\n"
            f"    merge(base, req.body);\n"
            f"    res.json({{ ok: true }});\n"
            f"}});\n"
        )
        safe = (
            f"const express = require('express');\n"
            f"const app = express();\n"
            f"app.use(express.json());\n\n"
            f"function safeMerge(dst, src) {{\n"
            f"    for (let key in src) {{\n"
            f"        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {{\n"
            f"            continue;\n"
            f"        }}\n"
            f"        if (typeof src[key] === 'object' && src[key] !== null) {{\n"
            f"            if (!dst[key]) dst[key] = {{}};\n"
            f"            safeMerge(dst[key], src[key]);\n"
            f"        }} else {{\n"
            f"            dst[key] = src[key];\n"
            f"        }}\n"
            f"    }}\n"
            f"    return dst;\n"
            f"}}\n\n"
            f"app.post('{rt}', (req, res) => {{\n"
            f"    const base = {{}};\n"
            f"    safeMerge(base, req.body);\n"
            f"    res.json({{ ok: true }});\n"
            f"}});\n"
        )
    elif fw == "Fastify":
        vuln = (
            f"const fastify = require('fastify')();\n\n"
            f"function deepAssign(target, source) {{\n"
            f"    for (const k of Object.keys(source)) {{\n"
            f"        if (source[k] && typeof source[k] === 'object') {{\n"
            f"            target[k] = target[k] || {{}};\n"
            f"            deepAssign(target[k], source[k]);\n"
            f"        }} else {{\n"
            f"            target[k] = source[k];\n"
            f"        }}\n"
            f"    }}\n"
            f"}}\n\n"
            f"fastify.post('{rt}', async (request, reply) => {{\n"
            f"    const appState = {{}};\n"
            f"    deepAssign(appState, request.body);\n"
            f"    return {{ updated: true }};\n"
            f"}});\n"
        )
        safe = (
            f"const fastify = require('fastify')();\n\n"
            f"function deepAssignSafe(target, source) {{\n"
            f"    for (const k of Object.keys(source)) {{\n"
            f"        if (k === '__proto__' || k === 'constructor' || k === 'prototype') {{\n"
            f"            continue;\n"
            f"        }}\n"
            f"        if (source[k] && typeof source[k] === 'object') {{\n"
            f"            target[k] = target[k] || {{}};\n"
            f"            deepAssignSafe(target[k], source[k]);\n"
            f"        }} else {{\n"
            f"            target[k] = source[k];\n"
            f"        }}\n"
            f"    }}\n"
            f"}}\n\n"
            f"fastify.post('{rt}', async (request, reply) => {{\n"
            f"    const appState = {{}};\n"
            f"    deepAssignSafe(appState, request.body);\n"
            f"    return {{ updated: true }};\n"
            f"}});\n"
        )
    else:  # Node.js http core
        vuln = (
            f"const http = require('http');\n\n"
            f"function populate(obj, path, val) {{\n"
            f"    const parts = path.split('.');\n"
            f"    let curr = obj;\n"
            f"    for (let i = 0; i < parts.length - 1; i++) {{\n"
            f"        curr = curr[parts[i]] = curr[parts[i]] || {{}};\n"
            f"    }}\n"
            f"    curr[parts[parts.length - 1]] = val;\n"
            f"}}\n\n"
            f"http.createServer((req, res) => {{\n"
            f"    let body = '';\n"
            f"    req.on('data', c => body += c);\n"
            f"    req.on('end', () => {{\n"
            f"        const data = JSON.parse(body || '{{}}');\n"
            f"        const target = {{}};\n"
            f"        populate(target, data.path, data.value);\n"
            f"        res.end('applied');\n"
            f"    }});\n"
            f"}});\n"
        )
        safe = (
            f"const http = require('http');\n\n"
            f"function safePopulate(obj, path, val) {{\n"
            f"    const parts = path.split('.');\n"
            f"    let curr = obj;\n"
            f"    for (let i = 0; i < parts.length - 1; i++) {{\n"
            f"        if (['__proto__', 'constructor', 'prototype'].includes(parts[i])) {{\n"
            f"            return;\n"
            f"        }}\n"
            f"        curr = curr[parts[i]] = curr[parts[i]] || {{}};\n"
            f"    }}\n"
            f"    const last = parts[parts.length - 1];\n"
            f"    if (!['__proto__', 'constructor', 'prototype'].includes(last)) {{\n"
            f"        curr[last] = val;\n"
            f"    }}\n"
            f"}}\n\n"
            f"http.createServer((req, res) => {{\n"
            f"    let body = '';\n"
            f"    req.on('data', c => body += c);\n"
            f"    req.on('end', () => {{\n"
            f"        const data = JSON.parse(body || '{{}}');\n"
            f"        const target = {{}};\n"
            f"        safePopulate(target, String(data.path || ''), data.value);\n"
            f"        res.end('applied');\n"
            f"    }});\n"
            f"}});\n"
        )
    return vuln, safe


def gen_cwe611(fw: str, var_idx: int) -> Tuple[str, str]:
    """CWE-611: XML External Entity (XXE)"""
    rt = ROUTES[var_idx % len(ROUTES)] + f"_{var_idx}"
    fn = f"{FN_NAMES[var_idx % len(FN_NAMES)]}_{var_idx}"

    if fw == "Flask":
        vuln = (
            f"from flask import Flask, request, jsonify\n"
            f"from lxml import etree\n\n"
            f"app = Flask(__name__)\n\n"
            f"@app.route('{rt}', methods=['POST'])\n"
            f"def {fn}():\n"
            f"    xml_payload = request.data\n"
            f"    parser = etree.XMLParser(resolve_entities=True, no_network=False)\n"
            f"    tree = etree.fromstring(xml_payload, parser=parser)\n"
            f"    return jsonify(tag=tree.tag)\n"
        )
        safe = (
            f"from flask import Flask, request, jsonify\n"
            f"import defusedxml.ElementTree as ET\n\n"
            f"app = Flask(__name__)\n\n"
            f"@app.route('{rt}', methods=['POST'])\n"
            f"def {fn}():\n"
            f"    xml_payload = request.data\n"
            f"    tree = ET.fromstring(xml_payload)\n"
            f"    return jsonify(tag=tree.tag)\n"
        )
    elif fw == "Django":
        vuln = (
            f"import xml.dom.minidom\n"
            f"from django.http import HttpResponse\n\n"
            f"def {fn}(request):\n"
            f"    xml_blob = request.body\n"
            f"    dom = xml.dom.minidom.parseString(xml_blob)\n"
            f"    return HttpResponse(dom.documentElement.tagName)\n"
        )
        safe = (
            f"import defusedxml.minidom\n"
            f"from django.http import HttpResponse\n\n"
            f"def {fn}(request):\n"
            f"    xml_blob = request.body\n"
            f"    dom = defusedxml.minidom.parseString(xml_blob)\n"
            f"    return HttpResponse(dom.documentElement.tagName)\n"
        )
    elif fw == "Raw Python":
        vuln = (
            f"from lxml import etree\n\n"
            f"def {fn}(xml_data):\n"
            f"    unsafe_parser = etree.XMLParser(resolve_entities=True, load_dtd=True)\n"
            f"    root = etree.fromstring(xml_data, parser=unsafe_parser)\n"
            f"    return root.attrib\n"
        )
        safe = (
            f"from lxml import etree\n\n"
            f"def {fn}(xml_data):\n"
            f"    safe_parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)\n"
            f"    root = etree.fromstring(xml_data, parser=safe_parser)\n"
            f"    return root.attrib\n"
        )
    elif fw == "Express.js":
        vuln = (
            f"const express = require('express');\n"
            f"const libxmljs = require('libxmljs');\n"
            f"const app = express();\n"
            f"app.use(express.text({{ type: 'application/xml' }}));\n\n"
            f"app.post('{rt}', (req, res) => {{\n"
            f"    const xmlDoc = libxmljs.parseXml(req.body, {{ noent: true, dtdload: true }});\n"
            f"    res.send(xmlDoc.root().name());\n"
            f"}});\n"
        )
        safe = (
            f"const express = require('express');\n"
            f"const libxmljs = require('libxmljs');\n"
            f"const app = express();\n"
            f"app.use(express.text({{ type: 'application/xml' }}));\n\n"
            f"app.post('{rt}', (req, res) => {{\n"
            f"    const xmlDoc = libxmljs.parseXml(req.body, {{ noent: false, dtdload: false }});\n"
            f"    res.send(xmlDoc.root().name());\n"
            f"}});\n"
        )
    elif fw == "Fastify":
        vuln = (
            f"const fastify = require('fastify')();\n"
            f"const libxmljs = require('libxmljs');\n\n"
            f"fastify.post('{rt}', async (request, reply) => {{\n"
            f"    const xml = request.body;\n"
            f"    const parsed = libxmljs.parseXmlString(xml, {{ noent: true }});\n"
            f"    return {{ tag: parsed.root().name() }};\n"
            f"}});\n"
        )
        safe = (
            f"const fastify = require('fastify')();\n"
            f"const libxmljs = require('libxmljs');\n\n"
            f"fastify.post('{rt}', async (request, reply) => {{\n"
            f"    const xml = request.body;\n"
            f"    const parsed = libxmljs.parseXmlString(xml, {{ noent: false, dtdload: false }});\n"
            f"    return {{ tag: parsed.root().name() }};\n"
            f"}});\n"
        )
    else:  # Node.js http core
        vuln = (
            f"const http = require('http');\n"
            f"const libxml = require('libxmljs');\n\n"
            f"http.createServer((req, res) => {{\n"
            f"    let data = '';\n"
            f"    req.on('data', chunk => data += chunk);\n"
            f"    req.on('end', () => {{\n"
            f"        const doc = libxml.parseXml(data, {{ dtdvalid: true, noent: true }});\n"
            f"        res.end(doc.root().text());\n"
            f"    }});\n"
            f"}});\n"
        )
        safe = (
            f"const http = require('http');\n"
            f"const libxml = require('libxmljs');\n\n"
            f"http.createServer((req, res) => {{\n"
            f"    let data = '';\n"
            f"    req.on('data', chunk => data += chunk);\n"
            f"    req.on('end', () => {{\n"
            f"        const doc = libxml.parseXml(data, {{ dtdvalid: false, noent: false }});\n"
            f"        res.end(doc.root().text());\n"
            f"    }});\n"
            f"}});\n"
        )
    return vuln, safe


# Bản đồ điều phối các hàm sinh mẫu theo CWE
CWE_DISPATCHER = {
    "CWE-89": gen_cwe89,
    "CWE-78": gen_cwe78,
    "CWE-22": gen_cwe22,
    "CWE-79": gen_cwe79,
    "CWE-502": gen_cwe502,
    "CWE-94": gen_cwe94,
    "CWE-918": gen_cwe918,
    "CWE-347": gen_cwe347,
    "CWE-1321": gen_cwe1321,
    "CWE-611": gen_cwe611,
}


# ==============================================================================
# HÀM ĐIỀU HÀNH CHÍNH
# ==============================================================================

def generate_augmented_dataset() -> List[Dict]:
    """
    Sinh chính xác 2.500 cặp đối ngẫu (5.000 mẫu) và xác thực cú pháp.
    """
    dataset: List[Dict] = []
    pairs_per_cwe = 250  # 10 CWE * 250 = 2.500 cặp = 5.000 mẫu
    python_syntax_checks = 0

    print("=" * 70)
    print(" BẮT ĐẦU QUY TRÌNH SINH TẬP DỮ LIỆU ĐỐI NGẪU (CONTRASTIVE DATASET)")
    print("=" * 70)

    for cwe in CWE_LIST:
        generator = CWE_DISPATCHER[cwe]
        cwe_clean = cwe.replace("-", "")

        for i in range(pairs_per_cwe):
            framework = FRAMEWORKS[i % len(FRAMEWORKS)]
            group_id = f"GROUP-2026-{cwe_clean}-VAR-{i:04d}"

            code_vuln, code_safe = generator(framework, i)

            # Kiểm tra tính hợp lệ cú pháp Python nếu snippet thuộc framework Python
            if framework in PYTHON_FRAMEWORKS:
                try:
                    ast.parse(code_vuln)
                    python_syntax_checks += 1
                except SyntaxError as e:
                    print(f"[!] SyntaxError trong Vuln snippet: {group_id} ({cwe}, {framework})")
                    print(e)
                    sys.exit(1)

                try:
                    ast.parse(code_safe)
                    python_syntax_checks += 1
                except SyntaxError as e:
                    print(f"[!] SyntaxError trong Benign snippet: {group_id} ({cwe}, {framework})")
                    print(e)
                    sys.exit(1)

            # Bản ghi Vulnerable (label = 1)
            dataset.append({
                "id": f"{group_id}-VULN",
                "group_id": group_id,
                "code": code_vuln,
                "label": 1,
                "cwe": cwe,
                "framework": framework,
            })

            # Bản ghi Benign / Remediated (label = 0)
            dataset.append({
                "id": f"{group_id}-BENIGN",
                "group_id": group_id,
                "code": code_safe,
                "label": 0,
                "cwe": cwe,
                "framework": framework,
            })

    print(f"[*] Đã xác thực thành công {python_syntax_checks} snippet Python qua `ast.parse`.")
    return dataset


def main():
    start_time = time.time()

    dataset = generate_augmented_dataset()
    total_records = len(dataset)
    num_vuln = sum(1 for item in dataset if item["label"] == 1)
    num_benign = sum(1 for item in dataset if item["label"] == 0)

    # Thống kê phân bổ theo CWE
    cwe_counts: Dict[str, int] = {}
    for item in dataset:
        cwe_counts[item["cwe"]] = cwe_counts.get(item["cwe"], 0) + 1

    # Thống kê phân bổ theo Framework
    fw_counts: Dict[str, int] = {}
    for item in dataset:
        fw_counts[item["framework"]] = fw_counts.get(item["framework"], 0) + 1

    # Lưu ra file data/augmented_5000.json
    output_dir = Path("data")
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "augmented_5000.json"

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(dataset, f, indent=2, ensure_ascii=False)

    elapsed_time = time.time() - start_time
    file_size_mb = os.path.getsize(output_path) / (1024 * 1024)

    # In báo cáo nghiệm thu kỹ thuật
    print("-" * 70)
    print(f" BÁO CÁO THỰC THI HOÀN TẤT:")
    print(f" - Tổng số mẫu đã sinh:       {total_records} snippets (Đạt chuẩn 5.000)")
    print(f" - Mẫu Vulnerable (label=1):  {num_vuln}")
    print(f" - Mẫu Benign (label=0):      {num_benign}")
    print(f" - Tỷ lệ cặp đối ngẫu:        2.500 cặp hoàn hảo (Chung group_id)")
    print(f" - Đường dẫn file:             {output_path.resolve()}")
    print(f" - Dung lượng file:           {file_size_mb:.2f} MB")
    print(f" - Thời gian thực thi:        {elapsed_time:.2f} giây")
    print("-" * 70)
    print(" PHÂN BỔ 10 DANH MỤC CWE (Mỗi danh mục 500 mẫu):")
    for cwe, count in cwe_counts.items():
        print(f"   * {cwe:<10}: {count} snippets (250 vuln / 250 benign)")
    print("-" * 70)
    print(" PHÂN BỔ 6 FRAMEWORK / NGỮ CẢNH:")
    for fw, count in fw_counts.items():
        print(f"   * {fw:<20}: {count} snippets")
    print("=" * 70)


if __name__ == "__main__":
    main()
