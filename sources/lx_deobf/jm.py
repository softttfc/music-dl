#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
jm.py - JS 混淆还原工具（安全版）
只做安全的静态字符串还原，不破坏语法结构。

用法:
    python jm.py 原文件.js [输出文件.js]
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
# 5. 安全替换：只替换参数里含字符串字面量的解码调用
# ============================================================
def replace_string_calls_safe(source, decoder):
    """
    只替换形如 _0x3c40(0x1f85, 'xxx') 或 _0x58b4(0x1f85, 'xxx') 的调用。
    严格条件：
      - 函数名是 _0x3c40 或 _0x58b4
      - 第一个参数是数字
      - 第二个参数是字符串字面量
      - 不在 return 语句开头
      - 结果字符串长度 > 1
    """
    # 找偏移量
    offsets = {}
    for fn_name in ('_0x3c40', '_0x58b4'):
        pat = re.compile(
            r'function\s+' + re.escape(fn_name) + r'\s*\([^)]*\)\s*\{'
            r'\s*\w+\s*=\s*\w+\s*-\s*(0x[0-9a-fA-F]+|\d+)',
            re.S
        )
        m = pat.search(source)
        if m:
            offsets[fn_name] = _parse_int(m.group(1)) or 0
        else:
            offsets[fn_name] = 0

    # 严格匹配
    call_pat = re.compile(
        r'(?<!return\s)'                          # 前面不是 return
        r'(_0x3c40|_0x58b4)'                      # 函数名
        r'\s*\(\s*'
        r"(?:'?(0x[0-9a-fA-F]+|\d+)'?)\s*,\s*"   # 第一个参数：数字
        r"'((?:[^'\\]|\\.)*)'"                    # 第二个参数：单引号字符串
        r'\s*\)'
    )

    def repl(m):
        fn = m.group(1)
        idx_token = m.group(2)
        literal = m.group(3)
        idx = _parse_int(idx_token)
        if idx is None:
            return m.group(0)
        off = offsets.get(fn, 0)
        real_idx = idx - off
        val = decoder.get(real_idx)
        # 关键：结果长度必须 > 1，否则不替换
        if val is None or len(val) < 2:
            return m.group(0)
        return json.dumps(val, ensure_ascii=False)

    return call_pat.sub(repl, source)


# ============================================================
# 6. 主流程：只做安全静态还原
# ============================================================
def deobfuscate(source):
    strings, arr_name = extract_string_array(source)
    if not strings:
        print("[!] 未找到字符串数组 _0x1f85")
        return source

    print(f"[+] 提取到字符串数组: {arr_name}, 共 {len(strings)} 项")
    decoder = StringDecoder(strings)

    result = replace_string_calls_safe(source, decoder)

    before = len(re.findall(r'_0x(?:3c40|58b4)\s*\(', source))
    after = len(re.findall(r'_0x(?:3c40|58b4)\s*\(', result))
    print(f"[+] _0x3c40/_0x58b4 调用: {before} -> {after}")

    return result


def main():
    if len(sys.argv) < 2:
        print("用法: python jm.py 原文件.js [输出文件.js]")
        sys.exit(1)

    src_path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) >= 3 else None

    if out_path is None:
        base, ext = os.path.splitext(src_path)
        out_path = base + ".deobf" + (ext or ".js")

    with open(src_path, "r", encoding="utf-8", errors="replace") as f:
        source = f.read()

    print(f"[+] 读取: {src_path} ({len(source)} 字符)")

    result = deobfuscate(source)

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(result)

    print(f"[+] 输出: {out_path} ({len(result)} 字符)")


if __name__ == "__main__":
    main()
