#!/usr/bin/env python3
"""skillspector-scan AST 分析器（只读）。

对目标技能中的 .py 文件做静态 AST 检查：
  - DC1/DC2/DC3/DC6/DC7/DC8：exec/eval/compile/__import__/getattr 等危险调用
  - DC4/DC5：subprocess / os.system 等外部进程执行
  - E1：网络调用信号
  - TT3/TT5：轻量污点（环境变量/文件/输入 → 执行或网络汇）

用法: python ast_check.py <file1.py> [file2.py ...]
输出: 单个 JSON 对象 {"findings": [...], "skips": [...]}
"""

import ast
import json
import re
import sys

DANGEROUS = {"exec", "eval", "compile", "__import__"}
DC_ID = {"exec": "DC1", "eval": "DC2", "compile": "DC6"}
PROCESS_SINKS = {
    "os.system", "os.popen", "os.execl", "os.execv", "os.spawn",
    "subprocess.run", "subprocess.call", "subprocess.Popen",
    "subprocess.check_output", "subprocess.check_call",
    "subprocess.getoutput", "subprocess.getstatusoutput",
    "pty.spawn", "commands.getoutput",
}
NET_SINKS = {
    "requests.post", "requests.put", "requests.patch", "requests.request",
    "urllib.request.urlopen", "urllib.request.urlretrieve", "urllib.urlopen",
    "http.client.HTTPConnection", "http.client.HTTPSConnection",
    "socket.send", "socket.sendall", "socket.connect",
    "smtplib.SMTP", "ftplib.FTP", "paramiko.SSHClient",
    "aiohttp.ClientSession", "httpx.post", "httpx.put", "httpx.patch",
    "urllib3.request",
}
FILE_SOURCES = {"open", "input", "sys.argv", "pickle.load", "yaml.load", "yaml.safe_load", "json.load"}
# 直接出现在调用参数中的环境变量来源表达式（无需先赋给变量的下标形式）
ENV_EXPRS = {"os.environ", "os.environ.get", "os.getenv", "getenv", "environ"}

JS_KEYWORDS = {
    "if", "for", "while", "switch", "catch", "function", "return", "typeof",
    "instanceof", "new", "delete", "void", "in", "of", "do", "else", "try",
    "case", "default", "throw", "yield", "await", "with",
}


def find_call_args(src, open_idx):
    """返回从 open_idx 起匹配到闭合括号的参数字符串（轻量 JS 词法）。"""
    depth = 0
    i = open_idx
    in_str = None
    while i < len(src):
        c = src[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == in_str:
                in_str = None
        else:
            if c in "\"'`":
                in_str = c
            elif c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    return src[open_idx + 1:i]
            elif c == "/" and i + 1 < len(src) and src[i + 1] == "/":
                nl = src.find("\n", i)
                if nl == -1:
                    return src[open_idx + 1:]
                i = nl
            elif c == "/" and i + 1 < len(src) and src[i + 1] == "*":
                end = src.find("*/", i + 2)
                if end == -1:
                    return src[open_idx + 1:]
                i = end + 1
        i += 1
    return src[open_idx + 1:]


def js_literal(args):
    """参数是否为单个字符串字面量（无拼接/无模板插值）。"""
    a = args.strip()
    if len(a) < 2:
        return False
    if a[0] in "\"'`" and a[-1] == a[0]:
        inner = a[1:-1]
        if "${" not in inner and "+" not in inner:
            return True
    return False


def analyze_js(path):
    """JS 行为启发式：动态执行、外部进程、网络调用与轻量污点。"""
    findings = []
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
            src = fh.read()
    except OSError:
        return findings
    has_cp = bool(re.search(
        r"require\s*\(\s*['\"]child_process['\"]|from\s*['\"]child_process['\"]",
        src))
    taint_re = re.compile(
        r"process\.env|fs\.readFile|req\.(query|body|params)|location\.search|"
        r"document\.cookie|argv\[|JSON\.parse|Math\.random")
    for m in re.finditer(r"([A-Za-z_$][\w$]*)\s*\(", src):
        name = m.group(1)
        if name in JS_KEYWORDS:
            continue
        line = src.count("\n", 0, m.start()) + 1
        args = find_call_args(src, m.end() - 1)
        prev = src[max(0, m.start() - 40):m.start()]
        tainted = bool(taint_re.search(args))
        if name in ("eval", "Function"):
            if js_literal(args):
                findings.append({"id": "DC2", "sev": "MED", "file": path, "line": line,
                                 "text": "%s() JS 动态执行（字面量）" % name})
            else:
                findings.append({"id": "DC8", "sev": "HIGH", "file": path, "line": line,
                                 "text": "%s() JS 动态执行（非字面量参数）" % name})
        elif name in ("exec", "execSync", "execFile", "execFileSync", "spawn",
                      "spawnSync", "fork") and has_cp:
            findings.append({"id": "DC4", "sev": "HIGH", "file": path, "line": line,
                             "text": "%s() JS 外部进程执行" % name})
            if tainted:
                findings.append({"id": "TT5", "sev": "HIGH", "file": path, "line": line,
                                 "text": "%s() 参数含外部输入（process.env/请求/文件等）" % name})
        elif name == "fetch" or (
                name in ("post", "put", "patch", "request", "send")
                and re.search(r"axios|https?\.|socket\.|ws\.", prev)):
            findings.append({"id": "E1", "sev": "MED", "file": path, "line": line,
                             "text": "%s() JS 网络调用" % name})
            if tainted:
                findings.append({"id": "TT3", "sev": "HIGH", "file": path, "line": line,
                                 "text": "%s() 参数含环境变量/外部输入（疑似外泄）" % name})
        elif name in ("exec", "eval", "Function") and tainted:
            findings.append({"id": "TT5", "sev": "HIGH", "file": path, "line": line,
                             "text": "%s() 参数含外部输入（疑似注入）" % name})
    return findings


def attr_name(node):
    """返回表达式名，如 os.system / subprocess.run / requests.post / os.environ。"""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parts = []
        cur = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""


def call_name(node):
    """返回调用表达式名；非调用节点返回空串。"""
    if not isinstance(node, ast.Call):
        return ""
    return attr_name(node.func)


def arg_is_literal(call):
    if not call.args:
        return False
    a = call.args[0]
    return isinstance(a, ast.Constant) and isinstance(a.value, str)


def collect_names(node, out):
    """收集表达式中的变量名与点号表达式名（递归进入字典/列表/元组/调用/下标），用于轻量污点。"""
    if node is None:
        return
    if isinstance(node, ast.Name):
        out.add(node.id)
    elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        for e in node.elts:
            collect_names(e, out)
    elif isinstance(node, ast.Dict):
        for k in node.keys:
            collect_names(k, out)
        for v in node.values:
            collect_names(v, out)
    elif isinstance(node, ast.Call):
        full = call_name(node)
        if full:
            out.add(full)
        for a in node.args:
            collect_names(a, out)
        for kw in node.keywords:
            collect_names(kw.value, out)
    elif isinstance(node, ast.Attribute):
        full = attr_name(node)
        if full:
            out.add(full)
        collect_names(node.value, out)
    elif isinstance(node, ast.Subscript):
        full = attr_name(node.value)
        if full:
            out.add(full)
        collect_names(node.value, out)
        collect_names(node.slice, out)


def analyze(path):
    findings = []
    skips = []
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
            src = fh.read()
        tree = ast.parse(src)
    except SyntaxError as exc:
        skips.append({"file": path, "line": getattr(exc, "lineno", 0),
                      "reason": "Python 语法解析失败，需人工确认"})
        return findings, skips

    env_reads = {}   # 变量名 -> 行号（来自 os.environ / os.getenv）
    file_reads = {}  # 变量名 -> 行号（来自 open / input / sys.argv）

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if not isinstance(tgt, ast.Name):
                    continue
                val = node.value
                n = call_name(val) if isinstance(val, ast.Call) else ""
                if n in ("os.getenv", "os.environ.get") or (
                    isinstance(val, ast.Subscript)
                    and attr_name(val.value) == "os.environ"
                ):
                    env_reads[tgt.id] = node.lineno
                if n in FILE_SOURCES:
                    file_reads[tgt.id] = node.lineno

        if not isinstance(node, ast.Call):
            continue
        n = call_name(node)

        if n in DANGEROUS:
            if n in ("exec", "eval") and not arg_is_literal(node):
                findings.append({"id": "DC8", "sev": "HIGH", "file": path,
                                 "line": node.lineno,
                                 "text": "%s(非字面量参数，疑似动态执行)" % n})
            elif n == "__import__":
                findings.append({"id": "DC3", "sev": "HIGH", "file": path,
                                 "line": node.lineno, "text": "__import__() 动态导入"})
            else:
                findings.append({"id": DC_ID.get(n, "DC1"), "sev": "HIGH",
                                 "file": path, "line": node.lineno,
                                 "text": "%s() 危险调用" % n})

        if n in PROCESS_SINKS:
            findings.append({"id": "DC4", "sev": "HIGH", "file": path,
                             "line": node.lineno,
                             "text": "%s() 执行外部进程" % n})

        if n == "getattr" and len(node.args) > 1 and not isinstance(node.args[1], ast.Constant):
            findings.append({"id": "DC7", "sev": "MED", "file": path,
                             "line": node.lineno, "text": "getattr() 动态属性名"})

        if n in NET_SINKS:
            findings.append({"id": "E1", "sev": "MED", "file": path,
                             "line": node.lineno, "text": "%s() 网络调用" % n})

        arg_names = set()
        for arg in node.args:
            collect_names(arg, arg_names)
        for kw in node.keywords:
            collect_names(kw.value, arg_names)
        for an in arg_names:
            env_src = an in env_reads or an in ENV_EXPRS
            file_src = an in file_reads or an in FILE_SOURCES
            if env_src and (n in PROCESS_SINKS or n in DANGEROUS or n in NET_SINKS):
                findings.append({"id": "TT3", "sev": "HIGH", "file": path,
                                 "line": node.lineno,
                                 "text": "%s() 参数来自环境变量 %s（读取于行 %s）"
                                         % (n, an, env_reads.get(an, ""))})
            if file_src and (n in PROCESS_SINKS or n in DANGEROUS):
                findings.append({"id": "TT5", "sev": "HIGH", "file": path,
                                 "line": node.lineno,
                                 "text": "%s() 参数来自文件/输入 %s" % (n, an)})

    # 函数参数 → 危险汇（外部输入流入执行入口）
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        params = {a.arg for a in node.args.args}
        for sub in ast.walk(node):
            if not isinstance(sub, ast.Call):
                continue
            n = call_name(sub)
            if n in DANGEROUS or n in PROCESS_SINKS:
                arg_names = set()
                for arg in sub.args:
                    collect_names(arg, arg_names)
                for kw in sub.keywords:
                    collect_names(kw.value, arg_names)
                for an in arg_names:
                    if an in params:
                        findings.append({"id": "TT5", "sev": "HIGH", "file": path,
                                         "line": sub.lineno,
                                         "text": "%s() 参数来自函数参数 %s（外部输入→执行）"
                                                 % (n, an)})
    return findings, skips


def main():
    files = [p for p in sys.argv[1:] if p]
    all_findings = []
    all_skips = []
    for path in files:
        if path.lower().endswith((".js", ".mjs", ".cjs")):
            all_findings.extend(analyze_js(path))
        else:
            f, s = analyze(path)
            all_findings.extend(f)
            all_skips.extend(s)
    print(json.dumps({"findings": all_findings, "skips": all_skips}, ensure_ascii=False))


if __name__ == "__main__":
    main()
