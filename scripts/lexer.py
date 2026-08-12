#!/usr/bin/env python3
"""轻量注释词法状态机（lexer/parser-aware，禁止 line.contains 式误判）。

输入：--self-test 自检；或文件路径列表（作为命令行参数）。
输出：JSON {"files": {<path>: {"comment_lines": [n, ...]}}}
      comment_lines 从 1 开始，表示该行属于注释（含跨行注释覆盖行）。

支持语言按扩展名分派：
  .py         Python   #   （排除字符串、f-string 文本、原始字符串）
  .js .mjs .cjs .ts .tsx .jsx   // /* */（排除字符串、模板串）
  .ps1 .psm1 .psd1 .sh .bash .zsh .rb   #（排除字符串）
  .html .htm .xml .svg   <!-- -->（排除标签属性内引号内容）
"""
import json
import sys


def _py_comments(text):
    lines = text.split("\n")
    out = set()
    in_triple = None
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        j = 0
        m = len(line)
        comment = False
        while j < m:
            ch = line[j]
            if in_triple:
                if line.startswith(in_triple * 3, j):
                    j += 3
                    in_triple = None
                    continue
                j += 1
                continue
            if ch in ("'", '"'):
                if line.startswith(ch * 3, j):
                    in_triple = ch
                    j += 3
                    continue
                q = ch
                k = j + 1
                while k < m:
                    if line[k] == "\\":
                        k += 2
                        continue
                    if line[k] == q:
                        break
                    k += 1
                j = k + 1
                continue
            if ch == "#":
                comment = True
                break
            j += 1
        if in_triple or comment:
            out.add(i + 1)
        i += 1
    return out


def _js_comments(text):
    lines = text.split("\n")
    out = set()
    in_block = False
    in_tpl = False
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        j = 0
        m = len(line)
        comment = False
        while j < m:
            if in_block:
                idx = line.find("*/", j)
                if idx < 0:
                    comment = True
                    break
                j = idx + 2
                in_block = False
                comment = True
                continue
            ch = line[j]
            if in_tpl:
                if ch == "`":
                    in_tpl = False
                elif ch == "\\":
                    j += 2
                    continue
                j += 1
                continue
            if ch == "`":
                in_tpl = True
                j += 1
                continue
            if ch in ('"', "'"):
                q = ch
                k = j + 1
                while k < m:
                    if line[k] == "\\":
                        k += 2
                        continue
                    if line[k] == q:
                        break
                    k += 1
                j = k + 1
                continue
            if ch == "/" and j + 1 < m:
                nxt = line[j + 1]
                if nxt == "/":
                    comment = True
                    break
                if nxt == "*":
                    in_block = True
                    j += 2
                    continue
            j += 1
        if in_block or in_tpl or comment:
            out.add(i + 1)
        i += 1
    return out


def _hash_comments(text):
    """PowerShell / Shell / Ruby：处理双引号与单引号字符串，排除内容中的 #。"""
    lines = text.split("\n")
    out = set()
    for i, line in enumerate(lines):
        j = 0
        m = len(line)
        comment = False
        while j < m:
            ch = line[j]
            if ch in ('"', "'"):
                q = ch
                k = j + 1
                while k < m:
                    if line[k] == "\\":
                        k += 2
                        continue
                    if line[k] == q:
                        break
                    k += 1
                j = k + 1
                continue
            if ch == "#":
                comment = True
                break
            j += 1
        if comment:
            out.add(i + 1)
    return out


def _html_comments(text):
    lines = text.split("\n")
    out = set()
    in_block = False
    for i, line in enumerate(lines):
        comment = False
        j = 0
        m = len(line)
        while j < m:
            if in_block:
                idx = line.find("-->", j)
                if idx < 0:
                    comment = True
                    break
                j = idx + 3
                in_block = False
                comment = True
                continue
            ch = line[j]
            if ch == "<" and line.startswith("<!--", j):
                in_block = True
                j += 4
                continue
            if ch in ('"', "'"):
                q = ch
                k = j + 1
                while k < m:
                    if line[k] == q:
                        break
                    k += 1
                j = k + 1
                continue
            j += 1
        if in_block or comment:
            out.add(i + 1)
    return out


def detect(text, ext):
    if ext in (".py", ".pyw"):
        return _py_comments(text)
    if ext in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"):
        return _js_comments(text)
    if ext in (".ps1", ".psm1", ".psd1", ".sh", ".bash", ".zsh", ".rb", ".pl", ".lua"):
        return _hash_comments(text)
    if ext in (".html", ".htm", ".xml", ".svg"):
        return _html_comments(text)
    return set()


def _self_test():
    cases = [
        ("x = \"# not a comment\"", ".py", set()),
        ("# real comment\ny = 1", ".py", {1}),
        ("s = f\"value #{1} ok\"  # tail", ".py", {1}),
        ("const x = \"// not a comment\";", ".js", set()),
        ("const y = \"/* not a comment */\";", ".js", set()),
        ("// real comment\nlet a = 1;", ".js", {1}),
        ("/* block\nspan */\nlet b = 2;", ".js", {1, 2}),
        ("$v = \"# not a comment\"; # tail", ".ps1", {1}),
        ("echo \"# no\"", ".sh", set()),
        ("<!-- not a comment -->", ".html", {1}),
        ("<div title=\"<!-- nope -->\">x</div>", ".html", set()),
    ]
    ok = True
    for text, ext, expect in cases:
        got = detect(text, ext)
        if got != expect:
            print("FAIL", ext, repr(text), "got", sorted(got), "expect", sorted(expect))
            ok = False
    if ok:
        print("lexer self-test OK")
    return 0 if ok else 1


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "--self-test":
        sys.exit(_self_test())
    files = sys.argv[1:]
    result = {}
    for path in files:
        ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
        ext = "." + ext
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        lines = detect(text, ext)
        if lines:
            result[path] = {"comment_lines": sorted(lines)}
    print(json.dumps({"files": result}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
