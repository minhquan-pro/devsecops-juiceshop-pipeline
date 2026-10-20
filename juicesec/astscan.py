"""Deeper static analysis: AST for Python, token/flow tracking for JS-like code.

This supplements the line-regex rules in :mod:`juicesec.core`. The goal is to
cut the false negatives the corpus documents (variables assigned on one line and
used as a sink on another, aliases, multi-line concatenation) while keeping the
zero-dependency promise: everything here uses the Python standard library only.

Two engines:

* :func:`analyze_python` parses real Python with the stdlib ``ast`` module and
  performs a small, conservative taint pass: it tracks which names hold a
  request-controlled value and whether that value reaches a dangerous sink.
* :func:`analyze_javascript` handles JS/TS snippets using a lightweight
  regex- and token-based data flow tracker (NOT a full ECMAScript AST parser).
  It does NOT claim complete JavaScript language parsing.
  Known unsupported flows include:
  - Inter-procedural call graphs and cross-module taint propagation
  - Complex nested closures, higher-order functions, and async callbacks
  - Object destructuring, spread assignments, and property access indirection
  - Computed property/method names and dynamic prototype modifications
"""
from __future__ import annotations

import ast
import re
from typing import Iterable

MAX_FINDINGS = 200

# --- Shared taxonomy -------------------------------------------------------

# Names that represent untrusted input in the Express/Node and Python web
# ecosystems. Matching is on a dotted prefix such as ``req.query``.
SOURCE_PREFIXES = (
    "req.body", "req.query", "req.params", "req.headers", "req.cookies",
    "request.body", "request.query", "request.args", "request.form",
    "request.json", "request.data", "request.GET", "request.POST",
    "location.search", "location.hash", "location.href", "document.cookie",
    "document.location", "window.location", "input", "params",
)

# (rule_id, human title, CWE, remediation)
SINK_RULES = {
    "innerhtml": ("SAST-AST-XSS", "Dữ liệu không tin cậy chảy vào HTML sink",
                  "CWE-79", "Dùng textContent hoặc làm sạch theo ngữ cảnh trước khi gán."),
    "document.write": ("SAST-AST-XSS", "Dữ liệu không tin cậy chảy vào document.write",
                       "CWE-79", "Thay document.write bằng API DOM an toàn có kiểm soát."),
    "eval": ("SAST-AST-EVAL", "Dữ liệu không tin cậy chảy vào eval",
             "CWE-95", "Loại bỏ eval; dùng bộ phân tích dữ liệu có schema."),
    "exec": ("SAST-AST-CMD", "Dữ liệu không tin cậy chảy vào lệnh hệ điều hành",
             "CWE-78", "Cố định executable và truyền tham số dạng mảng, không qua shell."),
    "sql": ("SAST-AST-SQL", "Dữ liệu không tin cậy ghép vào câu SQL",
            "CWE-89", "Dùng truy vấn tham số hóa cho mọi giá trị."),
    "path": ("SAST-AST-PATH", "Dữ liệu không tin cậy dùng làm đường dẫn tệp",
             "CWE-22", "Ánh xạ ID sang tệp cố định và kiểm tra quan hệ thư mục sau resolve."),
    "ssrf": ("SAST-AST-SSRF", "Dữ liệu không tin cậy dùng làm đích HTTP",
             "CWE-918", "Allowlist đích và kiểm tra địa chỉ kết nối thực."),
    "deserialize": ("SAST-AST-DESER", "Giải tuần tự hóa đối tượng không tin cậy",
                    "CWE-502", "Dùng JSON có schema thay vì khôi phục đối tượng."),
    "xml": ("SAST-AST-XXE", "Parser XML bật thực thể ngoài với dữ liệu không tin cậy",
            "CWE-611", "Tắt DTD và external entity ở parser."),
    "jwt": ("SAST-AST-JWT", "Xác thực token không kiểm tra chữ ký",
            "CWE-347", "Dùng verify với thuật toán cố định trước khi cấp quyền."),
    "trust": ("SAST-AST-TRUST", "Bỏ qua cơ chế làm sạch của framework",
              "CWE-79", "Xác minh luồng dữ liệu; tránh tin cậy HTML từ người dùng."),
    "bac": ("SAST-AST-BAC", "Truy vấn đối tượng theo ID mà không ràng buộc chủ sở hữu",
            "CWE-639", "Thêm điều kiện chủ sở hữu vào truy vấn ở tầng máy chủ."),
    "csrf": ("SAST-AST-CSRF", "Thay đổi trạng thái qua phương thức GET",
             "CWE-352", "Dùng POST/PUT kèm token CSRF và kiểm tra Origin."),
}

# SQL keywords that mark a string as a query fragment.
_SQL_RE = re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE|FROM\s+\w|WHERE\s+\w)\b", re.I)
# File-read helpers that treat their first argument as a path.
_PATH_FUNCS = re.compile(r"(?:readFile|sendFile|readFileSync|createReadStream|open)\s*$")
# Outbound HTTP helpers that take a URL/endpoint as their first argument.
_SSRF_FUNCS = re.compile(r"(?:fetch|axios\.get|axios\.post|requests\.get|requests\.post|urlopen)\s*$")
# Deserialization sinks.
_DESER_FUNCS = re.compile(r"(?:pickle\.loads|yaml\.load|unserialize)\s*$")
# Command sinks.
_EXEC_FUNCS = re.compile(r"(?:child_process\.)?(?:exec|execSync|system)\s*$")
# Semantic patterns the flow engine can also model.
# Token decode without a verify call in the same snippet.
_JWT_MISUSE_RE = re.compile(r"(?:jwt|jsonwebtoken|jose)\.decode\s*\(")
_JWT_WRAPPER_RE = re.compile(r"\b[\w$]*(?:decode|parse)[\w$]*token[\w$]*\s*\(|\bdecodeToken\w*\s*\(", re.I)
# Framework sanitizer bypass (Angular DomSanitizer).
_TRUST_BYPASS_RE = re.compile(r"bypassSecurityTrust(?:Html|Script|Url|ResourceUrl|Style)\s*\(")
# ORM lookups by id that do not constrain the owning subject.
_ORM_FETCH_RE = re.compile(r"\.(?:findByPk|findByID|findById|findUnique)\s*\(")
_ORM_OWNER_RE = re.compile(r"(?:UserId|user_id|ownerId|owner_id|where\s*:)", re.I)
# State-changing route registered with GET (CSRF/insecure-method smell).
_STATE_ROUTE_RE = re.compile(r"\.(?:get)\s*\(\s*[\"'][^\"']*(?:change|update|delete|remove|create|set|add|reset)[^\"']*[\"']", re.I)
_CSRF_GUARD_RE = re.compile(r"csrf|xsrf|verifyToken", re.I)



def is_benign_token_decode(source: str) -> bool:
    """True when a token ``decode`` is not used for an authorization decision.

    The corpus documents that ``jwt.decode`` for a debug preview is not a
    vulnerability. We treat a decode as benign when the snippet contains no
    authorization keyword and no ``verify`` alternative is needed: without a
    decision based on the decoded claims, there is nothing to bypass.
    """
    if not _JWT_MISUSE_RE.search(source) and not _JWT_WRAPPER_RE.search(source):
        return True  # no decode at all; nothing to suppress
    if re.search(r"(?:jwt|jsonwebtoken|jose)\.verify\s*\(", source):
        return True  # a real verification is present
    return not re.search(r"\b(?:allow|authorize|isAdmin|role|permission|grant|checkAccess)\b",
                         source, re.I)


def finding(rule_id, title, severity, confidence, cwe, evidence, remediation):
    return {"rule_id": rule_id, "title": title, "severity": severity,
            "confidence": confidence, "status": "needs_review", "cwe": cwe,
            "engine": "ast_taint", "evidence": evidence, "remediation": remediation}



# --- Python engine ---------------------------------------------------------

def _attr_dotted(node: ast.AST) -> str:
    """Return ``a.b.c`` for an Attribute chain, else ''."""
    parts = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""


def _is_source(node: ast.AST) -> bool:
    dotted = _attr_dotted(node)
    if dotted:
        return any(dotted == p or dotted.startswith(p + ".") for p in SOURCE_PREFIXES)
    if isinstance(node, ast.Subscript):
        return _is_source(node.value)
    return False


def _call_dotted(node: ast.Call) -> str:
    return _attr_dotted(node.func) or (node.func.id if isinstance(node.func, ast.Name) else "")


class _PythonTaint(ast.NodeVisitor):
    """Inter-procedural taint tracker with call graph and function summaries."""

    def __init__(self, filename: str, tree: ast.Module):
        self.filename = filename
        self.tainted: set[str] = set()
        self.aliases: dict[str, str] = {}  # local name -> dotted callable it points at
        self.findings: list = []
        
        # Inter-procedural analysis infrastructure
        self.call_graph: dict[str, set[str]] = {}  # caller -> {callees}
        self.function_summaries: dict[str, dict] = {}  # func_name -> {params_tainted, returns_tainted, has_sink}
        self.current_function: str = "<module>"
        self.return_tainted: bool = False
        
        # Build call graph and summaries in first pass
        self._build_call_graph(tree)

    def _build_call_graph(self, tree: ast.Module):
        """First pass: extract all functions and build call graph skeleton."""
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_name = node.name
                self.function_summaries[func_name] = {
                    "params": [arg.arg for arg in node.args.args],
                    "params_tainted": set(),
                    "returns_tainted": False,
                    "has_sink": False,
                    "calls": set()
                }
                # Record calls within this function
                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        callee = _call_dotted(child)
                        if callee:
                            self.function_summaries[func_name]["calls"].add(callee)

    def _propagate_taint_through_call(self, func_name: str, args: list) -> bool:
        """Check if calling func_name with these args produces tainted output."""
        if func_name not in self.function_summaries:
            # External function - conservatively assume taint propagates if any arg is tainted
            return any(self._expr_tainted(arg) for arg in args)
        
        summary = self.function_summaries[func_name]
        
        # If any tainted arg corresponds to a param that flows to return, result is tainted
        for i, arg in enumerate(args):
            if i < len(summary["params"]) and self._expr_tainted(arg):
                param_name = summary["params"][i]
                if param_name in summary["params_tainted"]:
                    return True
        
        return summary["returns_tainted"]

    def _record(self, key, line, snippet, confidence="medium"):
        if len(self.findings) >= MAX_FINDINGS:
            return
        rule_id, title, cwe, fix = SINK_RULES[key]
        self.findings.append(finding(rule_id, title, "medium", confidence, cwe,
                                     {"file": self.filename, "line": line, "snippet": snippet[:200]},
                                     fix))

    def _expr_tainted(self, node) -> bool:
        if node is None:
            return False
        if _is_source(node):
            return True
        if isinstance(node, ast.Name):
            return node.id in self.tainted
        # Inter-procedural: check if call returns tainted value
        if isinstance(node, ast.Call):
            callee = _call_dotted(node)
            if callee and self._propagate_taint_through_call(callee, node.args):
                return True
        if isinstance(node, (ast.BinOp, ast.JoinedStr, ast.FormattedValue,
                              ast.Attribute, ast.Subscript, ast.Call)):
            return any(self._expr_tainted(child) for child in ast.iter_child_nodes(node))
        return False

    def visit_Assign(self, node: ast.Assign):
        tainted = self._expr_tainted(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                if tainted:
                    self.tainted.add(target.id)
                else:
                    self.tainted.discard(target.id)
                # Track `alias = module.sink` so aliased sinks are still caught.
                alias = _attr_dotted(node.value)
                if alias:
                    self.aliases[target.id] = alias
                elif isinstance(node.value, ast.Name) and node.value.id in self.aliases:
                    self.aliases[target.id] = self.aliases[node.value.id]
        if tainted and isinstance(node.value, (ast.BinOp, ast.JoinedStr)):
            self._record("sql", node.lineno, "SQL assembled from untrusted input")
        self.generic_visit(node)

    def _resolve(self, dotted: str) -> str:
        head, _, tail = dotted.partition(".")
        if head in self.aliases:
            return self.aliases[head] + (("." + tail) if tail else "")
        return dotted

    def visit_Return(self, node: ast.Return):
        """Track if function returns tainted value."""
        if node.value and self._expr_tainted(node.value):
            self.return_tainted = True
            if self.current_function in self.function_summaries:
                self.function_summaries[self.current_function]["returns_tainted"] = True
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        dotted = self._resolve(_call_dotted(node))
        first = node.args[0] if node.args else None
        line = getattr(node, "lineno", 0)
        
        # Mark that current function has sink if tainted data reaches it
        has_sink = False
        if dotted.endswith("eval") and self._expr_tainted(first):
            self._record("eval", line, "eval(untrusted)", "high")
            has_sink = True
        elif _EXEC_FUNCS.search(dotted) and self._expr_tainted(first):
            self._record("exec", line, f"{dotted}(untrusted)", "high")
            has_sink = True
        elif _DESER_FUNCS.search(dotted) and self._expr_tainted(first):
            self._record("deserialize", line, f"{dotted}(untrusted)", "high")
            has_sink = True
        elif _PATH_FUNCS.search(dotted) and self._expr_tainted(first):
            self._record("path", line, f"{dotted}(untrusted path)", "high")
            has_sink = True
        elif _SSRF_FUNCS.search(dotted) and self._expr_tainted(first):
            self._record("ssrf", line, f"{dotted}(untrusted url)", "high")
            has_sink = True
        elif dotted.endswith("execute") or dotted.endswith("query"):
            if any(self._expr_tainted(a) for a in node.args):
                self._record("sql", line, f"{dotted}(untrusted sql)", "high")
                has_sink = True
        
        if has_sink and self.current_function in self.function_summaries:
            self.function_summaries[self.current_function]["has_sink"] = True
        
        self.generic_visit(node)

    def visit_keyword(self, node: ast.keyword):
        if node.arg in ("resolve_entities", "load_dtd", "noent"):
            if isinstance(node.value, ast.Constant) and node.value.value is True:
                self._record("xml", getattr(node.value, "lineno", 0),
                             f"{node.arg}=True", "medium")
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Analyze function with inter-procedural context."""
        saved_function = self.current_function
        saved_tainted = set(self.tainted)
        saved_aliases = dict(self.aliases)
        saved_return = self.return_tainted
        
        self.current_function = node.name
        self.return_tainted = False
        
        # Mark parameters as potentially tainted for summary building
        new_tainted = set()
        for arg in node.args.args:
            # Conservative: assume all params could receive tainted input
            new_tainted.add(arg.arg)
        
        self.tainted = new_tainted
        self.generic_visit(node)
        
        # Record which params flow to tainted expressions
        if node.name in self.function_summaries:
            for param in node.args.args:
                if param.arg in saved_tainted or self.return_tainted:
                    self.function_summaries[node.name]["params_tainted"].add(param.arg)
        
        # Restore context
        self.current_function = saved_function
        self.tainted = saved_tainted
        self.aliases = saved_aliases
        self.return_tainted = saved_return

    visit_AsyncFunctionDef = visit_FunctionDef
    
    def visit_ClassDef(self, node: ast.ClassDef):
        """Analyze class methods with namespace context."""
        saved_tainted = set(self.tainted)
        saved_aliases = dict(self.aliases)
        self.generic_visit(node)
        self.tainted = saved_tainted
        self.aliases = saved_aliases


MAX_AST_DEPTH = 150


def _check_ast_depth(node: ast.AST, depth: int = 0, max_depth: int = MAX_AST_DEPTH) -> bool:
    """Pre-scan depth check to prevent DoS / RecursionError from pathological AST nesting."""
    if depth > max_depth:
        return False
    for child in ast.iter_child_nodes(node):
        if not _check_ast_depth(child, depth + 1, max_depth):
            return False
    return True


def analyze_python(source: str, filename: str) -> list:
    try:
        tree = ast.parse(source, filename=filename)
    except (SyntaxError, RecursionError, MemoryError):
        return []
    except Exception:
        return []

    try:
        if not _check_ast_depth(tree):
            return []
    except (RecursionError, MemoryError):
        return []

    try:
        visitor = _PythonTaint(filename, tree)
        visitor.visit(tree)
        return visitor.findings
    except (RecursionError, MemoryError):
        return []


# --- JavaScript-like engine ------------------------------------------------

_ASSIGN_RE = re.compile(r"(?:var|let|const)?\s*([A-Za-z_$][\w$]*)\s*=\s*(.+?);?\s*$")
_SINK_CALL_RE = re.compile(r"(?P<callee>[A-Za-z_$][\w$.]*)\s*\((?P<arg>[^()]*)\)")


def _strip_comments(text: str) -> str:
    """Remove JS comments while preserving strings and newline positions."""
    out: list[str] = []
    i = 0
    n = len(text)
    in_quote: str | None = None

    while i < n:
        char = text[i]
        if in_quote:
            out.append(char)
            if char == "\\" and i + 1 < n:
                i += 1
                out.append(text[i])
            elif char == in_quote:
                in_quote = None
            i += 1
            continue

        if char in ("'", '"', "`"):
            in_quote = char
            out.append(char)
            i += 1
            continue

        if char == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue

        if char == "/" and i + 1 < n and text[i + 1] == "*":
            out.append(" ")  # Comments separate tokens, including an empty /**/.
            i += 2
            while i < n:
                if text[i] == "*" and i + 1 < n and text[i + 1] == "/":
                    i += 2
                    break
                if text[i] == "\n":
                    out.append("\n")
                else:
                    out.append(" ")
                i += 1
            continue

        out.append(char)
        i += 1

    return "".join(out)


def _split_statements(line: str) -> list[str]:
    """Split line by ';' only when the semicolon is outside string literals."""
    statements: list[str] = []
    current: list[str] = []
    in_quote: str | None = None
    i = 0
    n = len(line)

    while i < n:
        char = line[i]
        if in_quote:
            current.append(char)
            if char == "\\" and i + 1 < n:
                i += 1
                current.append(line[i])
            elif char == in_quote:
                in_quote = None
            i += 1
            continue

        if char in ("'", '"', "`"):
            in_quote = char
            current.append(char)
            i += 1
            continue

        if char == ";":
            stmt = "".join(current).strip()
            if stmt:
                statements.append(stmt)
            current = []
            i += 1
            continue

        current.append(char)
        i += 1

    stmt = "".join(current).strip()
    if stmt:
        statements.append(stmt)
    return statements


def _is_source_expr(expr: str) -> bool:
    return any(re.search(r"(?:^|[^\w.])" + re.escape(p), expr) for p in SOURCE_PREFIXES)


def _source_in(expr: str, tainted: set) -> bool:
    if _is_source_expr(expr):
        return True
    return any(name in tainted for name in re.findall(r"[A-Za-z_$][\w$]*", expr))


def analyze_javascript(source: str, filename: str) -> list:
    """Track single-assignment data flow from JS sources to sinks using regex and tokens.

    NOTE: This is a lightweight heuristic flow tracker, not a full JS AST parser.
    The tracker keeps a set of tainted variable names plus a set of variables
    known to hold a SQL string. Comments are stripped with string-awareness first,
    preventing false positives on commented-out sinks while preserving strings.
    """
    out: list = []
    tainted: set[str] = set()
    sql_vars: set[str] = set()
    aliases: dict[str, str] = {}

    def record(key, line, snippet, confidence="medium"):
        if len(out) >= MAX_FINDINGS:
            return
        rule_id, title, cwe, fix = SINK_RULES[key]
        out.append(finding(rule_id, title, "medium", confidence, cwe,
                           {"file": filename, "line": line, "snippet": snippet[:200]}, fix))

    def resolve(callee: str) -> str:
        head, _, tail = callee.partition(".")
        if head in aliases:
            return aliases[head] + (("." + tail) if tail else "")
        return callee

    cleaned_source = _strip_comments(source)
    for number, (raw, code) in enumerate(zip(source.splitlines(), cleaned_source.splitlines()), 1):
        if not code.strip():
            continue
        # Process each ;-separated statement in order, respecting quotes
        for statement in _split_statements(code):
            if not statement.strip():
                continue
            _process_statement(statement, raw, number, source, tainted, sql_vars, aliases, record, resolve)
    return out


def _process_statement(code, raw, number, source, tainted, sql_vars, aliases, record, resolve):
    """Handle one JS-like statement: learn assignments, then detect sinks."""
    # 1) Learn assignments so later sinks can see the taint. Handle the
    #    multi-line case: an earlier SQL variable reused in a later concat.
    m = _ASSIGN_RE.search(code)
    if m:
        name, rhs = m.group(1), m.group(2)
        if _source_in(rhs, tainted):
            tainted.add(name)
        else:
            tainted.discard(name)
        if bool(_SQL_RE.search(rhs)) or any(v in sql_vars for v in _words(rhs)):
            sql_vars.add(name)
        # Track `alias = module.sink` and `alias = otherAlias`.
        rhs_clean = rhs.strip().rstrip(";").strip()
        if re.fullmatch(r"[A-Za-z_$][\w$.]*", rhs_clean):
            aliases[name] = aliases.get(rhs_clean, rhs_clean)

    # 2a) property-assignment sinks: x.innerHTML = tainted
    prop = re.search(r"\.(innerHTML|outerHTML)\s*=\s*(.+?);?\s*$", code)
    if prop and _source_in(prop.group(2), tainted):
        record("innerhtml", number, raw, "high")

    # 2b) function-call sinks.
    for call in _SINK_CALL_RE.finditer(code):
        callee, arg = resolve(call.group("callee")), call.group("arg").strip()
        tainted_arg = _source_in(arg, tainted)
        if callee.endswith(("document.write",)) and tainted_arg:
            record("document.write", number, raw, "high")
        elif callee == "eval" and tainted_arg:
            record("eval", number, raw, "high")
        elif _EXEC_FUNCS.search(callee) and tainted_arg:
            record("exec", number, raw, "high")
        elif _PATH_FUNCS.search(callee) and tainted_arg:
            record("path", number, raw, "high")
        elif _SSRF_FUNCS.search(callee) and tainted_arg:
            record("ssrf", number, raw, "high")
        elif _DESER_FUNCS.search(callee) and tainted_arg:
            record("deserialize", number, raw, "high")
        elif callee.endswith((".execute", ".query")) and tainted_arg:
            record("sql", number, raw, "high")
        # 2c) sink whose argument is a known SQL string variable.
        elif callee.endswith((".execute", ".query")) and arg in sql_vars:
            record("sql", number, raw, "medium")

    # 2d) dynamic HTML property sink: node["inner"+"HTML"] = tainted
    dyn = re.search(r"\[\s*['\"][^'\"]*['\"]\s*\+[^\]]*\]\s*=\s*(.+?);?\s*$", code)
    if dyn and ("html" in code.lower()) and _source_in(dyn.group(1), tainted):
        record("innerhtml", number, raw, "medium")

    # 3) semantic rules that do not depend on data flow.
    if (_JWT_MISUSE_RE.search(code) or _JWT_WRAPPER_RE.search(code)) \
            and re.search(r"\b(?:allow|authorize|isAdmin|role|permission|grant|checkAccess)\b", source, re.I):
        # A same-snippet verify() call means the decode is likely benign.
        if not re.search(r"(?:jwt|jsonwebtoken|jose)\.verify\s*\(", source):
            record("jwt", number, raw, "medium")
    if _TRUST_BYPASS_RE.search(code):
        record("trust", number, raw, "high")
    if _ORM_FETCH_RE.search(code) and not _ORM_OWNER_RE.search(code):
        record("bac", number, raw, "medium")
    if _STATE_ROUTE_RE.search(code) and not _CSRF_GUARD_RE.search(code):
        record("csrf", number, raw, "medium")




def _words(expr: str) -> list:
    return re.findall(r"[A-Za-z_$][\w$]*", expr)


# --- Dispatcher ------------------------------------------------------------

def analyze_ast(source: str, filename: str = "snippet.txt") -> list:
    """Pick the right engine by file extension, then fall back to JS-like."""
    if not isinstance(source, str):
        raise ValueError("source must be a string")
    if len(source.encode("utf-8")) > 200000:
        raise ValueError("source exceeds 200000 UTF-8 bytes")
    lowered = filename.lower()
    if lowered.endswith(".py"):
        return analyze_python(source, filename)
    if lowered.endswith((".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")):
        return analyze_javascript(source, filename)
    # Unknown extension: try Python first, then the JS-like tracker.
    findings = analyze_python(source, filename)
    return findings or analyze_javascript(source, filename)


def rule_ids(findings: Iterable[dict]) -> list:
    return [f["rule_id"] for f in findings]

