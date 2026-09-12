#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
jm.py - JS 混淆还原工具（支持运行时回填）
用法:
    python jm.py 原文件.js [输出文件.js] [runtime-dump.json]
"""

import re
import sys
import os
import json


# ============================================================
# 1. 自定义 base64 解码
# ============================================================
def _b64_variant_decode(data):
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/='
    result = []
    buffer = 0
    bits = 0
    for ch in data:
        idx = chars.find(ch)
        if idx == -1:
            continue
        buffer = (buffer << 6) | idx
        bits += 6
        if bits >= 8:
            bits -= 8
            result.append((buffer >> bits) & 0xFF)
    raw = bytes(result).decode('latin-1')
    try:
        return _percent_decode(raw)
    except Exception:
        return raw


def _percent_decode(s):
    result = []
    i = 0
    while i < len(s):
        if s[i] == '%' and i + 2 < len(s):
            try:
                byte = int(s[i + 1:i + 3], 16)
                result.append(chr(byte))
                i += 3
                continue
            except ValueError:
                pass
        result.append(s[i])
        i += 1
    raw = ''.join(result)
    try:
        return raw.encode('latin-1').decode('utf-8')
    except Exception:
        return raw


# ============================================================
# 2. 提取字符串数组
# ============================================================
def extract_string_array(source):
    pattern = re.compile(
        r'function\s+_0x1f85\s*\(\s*\)\s*\{\s*'
        r'const\s+(_0x[0-9a-fA-F]+)\s*=\s*\[(.*?)\]\s*;',
        re.S
    )
    m = pattern.search(source)
    if not m:
        return None, None
    arr_name = m.group(1)
    body = m.group(2)
    strings = re.findall(r"'((?:[^'\\]|\\.)*)'", body)
    strings = [s.replace("\\'", "'").replace('\\\\', '\\') for s in strings]
    return strings, arr_name


# ============================================================
# 3. 字符串解码器
# ============================================================
class StringDecoder:
    def __init__(self, strings):
        self.strings = strings
        self.cache = {}

    def get(self, index):
        if index < 0 or index >= len(self.strings):
            return None
        raw = self.strings[index]
        if raw in self.cache:
            return self.cache[raw]
        try:
            decoded = _b64_variant_decode(raw)
        except Exception:
            decoded = raw
        self.cache[raw] = decoded
        return decoded


# ============================================================
# 4. 解析整数
# ============================================================
def _parse_int(token):
    token = token.strip()
    try:
        if token.startswith('-'):
            return -int(token[1:], 0)
        return int(token, 0)
    except ValueError:
        return None


# ============================================================
# 5. 替换 _0x3c40 / _0x58b4 调用
# ============================================================
def replace_string_calls(source, decoder, arr_name):
    offsets = {}
    for fn_name in ('_0x3c40', '_0x58b4'):
        pat = re.compile(
            r'function\s+' + re.escape(fn_name) + r'\s*\([^)]*\)\s*\{'
            r'\s*\w+\s*=\s*\w+\s*-\s*(0x[0-9a-fA-F]+|\d+)',
            re.S
        )
        m = pat.search(source)
        if m:
            offsets[fn_name] = _parse_int(m.group(1))
        else:
            pat2 = re.compile(
                r'function\s+' + re.escape(fn_name) + r'\s*\([^)]*\)\s*\{'
                r'\s*\w+\s*=\s*\w+\s*-\s*\(([^)]+)\)',
                re.S
            )
            m2 = pat2.search(source)
            if m2:
                try:
                    offsets[fn_name] = int(eval(m2.group(1), {"__builtins__": {}}, {}))
                except Exception:
                    offsets[fn_name] = 0
            else:
                offsets[fn_name] = 0

    call_pat = re.compile(
        r'(_0x3c40|_0x58b4)\s*\(\s*'
        r"('?)(0x[0-9a-fA-F]+|\d+)\2\s*,\s*"
        r"(?:'([^']*)'|\"([^\"]*)\")\s*\)"
    )

    def repl(m):
        fn = m.group(1)
        idx_token = m.group(3)
        literal = m.group(4) if m.group(4) is not None else m.group(5)
        idx = _parse_int(idx_token)
        if idx is None:
            return m.group(0)
        off = offsets.get(fn, 0)
        real_idx = idx - off
        val = decoder.get(real_idx)
        if val is None:
            return m.group(0)
        return json.dumps(val, ensure_ascii=False)

    return call_pat.sub(repl, source)


# ============================================================
# 6. 用运行时字符串回填
# ============================================================
def replace_with_runtime_strings(source, runtime_strings):
    candidates = sorted(set(runtime_strings), key=len, reverse=True)
    call_pat = re.compile(r"(_0x[0-9a-fA-F]{4,8})\s*\(([^()]*)\)")

    def repl(m):
        args = m.group(2)
        lits = re.findall(r"'((?:[^'\\]|\\.)*)'|\"((?:[^\"\\]|\\.)*)\"", args)
        lits = [a or b for a, b in lits]
        if not lits:
            return m.group(0)
        joined = "".join(lits)
        for cand in candidates:
            if cand and cand in joined:
                return json.dumps(cand, ensure_ascii=False)
        for lit in lits:
            for cand in candidates:
                if cand and cand == lit:
                    return json.dumps(cand, ensure_ascii=False)
        return m.group(0)

    return call_pat.sub(repl, source)


# ============================================================
# 7. 主流程
# ============================================================
def deobfuscate(source):
    strings, arr_name = extract_string_array(source)
    if not strings:
        print("[!] 未找到字符串数组 _0x1f85")
        return source
    print(f"[+] 提取到字符串数组: {arr_name}, 共 {len(strings)} 项")
    decoder = StringDecoder(strings)
    result = replace_string_calls(source, decoder, arr_name)
    before = len(re.findall(r'_0x(?:3c40|58b4)\s*\(', source))
    after = len(re.findall(r'_0x(?:3c40|58b4)\s*\(', result))
    print(f"[+] _0x3c40/_0x58b4 调用: {before} -> {after}")
    return result


def deobfuscate_with_runtime(source, runtime_json_path):
    with open(runtime_json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    runtime_strings = data.get("strings", [])
    print(f"[+] 运行时字符串: {len(runtime_strings)} 条")
    result = deobfuscate(source)
    result = replace_with_runtime_strings(result, runtime_strings)
    return result


def main():
    if len(sys.argv) < 2:
        print("用法: python jm.py 原文件.js [输出文件.js] [runtime-dump.json]")
        sys.exit(1)

    src_path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) >= 3 else None
    runtime_path = sys.argv[3] if len(sys.argv) >= 4 else None

    if out_path is None:
        base, ext = os.path.splitext(src_path)
        out_path = base + ".deobf" + (ext or ".js")

    with open(src_path, "r", encoding="utf-8", errors="replace") as f:
        source = f.read()

    print(f"[+] 读取: {src_path} ({len(source)} 字符)")

    if runtime_path and os.path.isfile(runtime_path):
        result = deobfuscate_with_runtime(source, runtime_path)
    else:
        result = deobfuscate(source)

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(result)

    print(f"[+] 输出: {out_path} ({len(result)} 字符)")


if __name__ == "__main__":
    main()
