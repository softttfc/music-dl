#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
jm.py - JS 混淆还原工具 v3
严格安全模式：
  1. 不碰任何 function 定义体
  2. 不碰 _0x3c40 / _0x58b4 的调用
  3. 只替换「代理函数调用」且参数全是字面量
"""

import re
import sys
import os
import json


# ============================================================
# 1. 提取字符串数组
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
    body = m.group(2)
    strings = re.findall(r"'((?:[^'\\]|\\.)*)'", body)
    strings = [s.replace("\\'", "'").replace('\\\\', '\\') for s in strings]
    return strings, m.group(1)


# ============================================================
# 2. 复现 _0x3c40 / _0x58b4 的解码逻辑
# ============================================================
_B64_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/='


def _b64_variant_decode(data):
    result = []
    buffer = 0
    bits = 0
    for ch in data:
        idx = _B64_CHARS.find(ch)
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


def _rc4(key, data):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + ord(key[i % len(key)])) % 256
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = []
    for ch in data:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out.append(chr(ord(ch) ^ s[(s[i] + s[j]) % 256]))
    return ''.join(out)


class Decoder:
    def __init__(self, strings):
        self.strings = strings
        self.cache = {}

    def decode(self, idx, key):
        if idx < 0 or idx >= len(self.strings):
            return None
        raw = self.strings[idx]
        cache_key = (idx, key)
        if cache_key in self.cache:
            return self.cache[cache_key]
        try:
            step1 = _b64_variant_decode(raw)
            result = _rc4(key, step1)
        except Exception:
            result = raw
        self.cache[cache_key] = result
        return result


# ============================================================
# 3. 解析代理函数定义
# ============================================================
def parse_wrappers(source):
    """
    严格匹配：
      function _0x581861(a,b,c,d,e,f,g){
          return _0x58b4(a - -0x15a, g);
      }
    返回：
      { '_0x581861': {'decoder': '_0x58b4', 'idx_arg': 0, 'idx_offset': -0x15a, 'key_arg': 6} }
    """
    wrappers = {}

    # 函数定义正则：严格匹配「单行 return 解码函数」的形式
    func_pat = re.compile(
        r'function\s+(_0x[0-9a-fA-F]{4,8})\s*\(([^)]*)\)\s*\{\s*'
        r'return\s+(_0x3c40|_0x58b4)\s*\(\s*'
        r'([^,]+?)\s*,\s*'
        r'([^,)]+?)\s*\)\s*;?\s*\}',
        re.S
    )

    for m in func_pat.finditer(source):
        fn_name = m.group(1)
        params_str = m.group(2)
        decoder = m.group(3)
        idx_expr = m.group(4).strip()
        key_expr = m.group(5).strip()

        params = [p.strip() for p in params_str.split(',') if p.strip()]

        idx_info = _parse_idx_expr(idx_expr, params)
        if not idx_info:
            continue

        if key_expr not in params:
            continue
        key_arg = params.index(key_expr)

        wrappers[fn_name] = {
            'decoder': decoder,
            'idx_arg': idx_info['arg'],
            'idx_offset': idx_info['offset'],
            'key_arg': key_arg,
            'params': params,
        }

    return wrappers


def _parse_idx_expr(expr, params):
    e = expr.replace(' ', '')
    # 匹配 `a-0x15a` 或 `a--0x15a` 或 `a- -0x15a`
    m = re.match(r'^(\w+)-(-?0x[0-9a-fA-F]+|-?\d+)$', e)
    if not m:
        return None
    arg_name = m.group(1)
    offset_str = m.group(2)
    if arg_name not in params:
        return None
    try:
        offset = int(offset_str, 0)
    except ValueError:
        return None
    return {'arg': params.index(arg_name), 'offset': offset}


# ============================================================
# 4. 解析字面量
# ============================================================
def _parse_literal(token):
    t = token.strip()
    m = re.match(r"^'((?:[^'\\]|\\.)*)'$", t)
    if m:
        return m.group(1).replace("\\'", "'").replace('\\\\', '\\')
    m = re.match(r'^"((?:[^"\\]|\\.)*)"$', t)
    if m:
        return m.group(1)
    t2 = t.replace(' ', '')
    try:
        return int(t2, 0)
    except ValueError:
        pass
    m = re.match(r'^-(0x[0-9a-fA-F]+|\d+)$', t2)
    if m:
        try:
            return -int(m.group(1), 0)
        except ValueError:
            return None
    return None


# ============================================================
# 5. 替换代理函数调用（严格安全）
# ============================================================
def replace_wrapper_calls(source, wrappers, decoder):
    """
    只替换：
      _0x581861(-0xd,-'0x89',...,'pdbH')
    且：
      - 函数名在 wrappers 里
      - 参数全是字面量
      - 不在 function 定义体内部
    """
    if not wrappers:
        print("[!] 没有解析到代理函数")
        return source

    print(f"[+] 解析到 {len(wrappers)} 个代理函数")

    # 先标记出所有 function 定义体的范围，避免替换
    # 简化做法：匹配 `function _0xXXXX(...){ ... }` 的整个块
    function_ranges = []
    func_block_pat = re.compile(
        r'function\s+_0x[0-9a-fA-F]{4,8}\s*\([^)]*\)\s*\{',
    )
    for m in func_block_pat.finditer(source):
        start = m.start()
        # 从 { 开始找匹配的 }
        brace_start = source.find('{', m.start())
        if brace_start == -1:
            continue
        depth = 0
        in_str = None
        i = brace_start
        while i < len(source):
            ch = source[i]
            if in_str:
                if ch == '\\':
                    i += 2
                    continue
                if ch == in_str:
                    in_str = None
            else:
                if ch in ("'", '"', '`'):
                    in_str = ch
                elif ch == '{':
                    depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0:
                        function_ranges.append((start, i + 1))
                        break
            i += 1

    def in_function_range(pos):
        for s, e in function_ranges:
            if s <= pos < e:
                return True
        return False

    # 匹配调用
    call_pat = re.compile(
        r'\b(_0x[0-9a-fA-F]{4,8})\s*\(([^()]*)\)'
    )

    replaced_count = [0]

    def repl(m):
        pos = m.start()
        if in_function_range(pos):
            return m.group(0)

        fn = m.group(1)
        if fn not in wrappers:
            return m.group(0)

        info = wrappers[fn]
        args_str = m.group(2)

        # 拆分参数
        if '(' in args_str or '[' in args_str or '{' in args_str:
            return m.group(0)
        args = [a.strip() for a in args_str.split(',') if a.strip()]

        if len(args) < len(info['params']):
            return m.group(0)

        values = []
        for a in args:
            v = _parse_literal(a)
            if v is None:
                return m.group(0)
            values.append(v)

        idx_arg = info['idx_arg']
        key_arg = info['key_arg']

        if idx_arg >= len(values) or key_arg >= len(values):
            return m.group(0)

        idx_value = values[idx_arg]
        key_value = values[key_arg]

        if not isinstance(idx_value, int):
            return m.group(0)
        if not isinstance(key_value, str):
            return m.group(0)

        real_idx = idx_value - info['idx_offset']
        result = decoder.decode(real_idx, key_value)
        if result is None:
            return m.group(0)

        replaced_count[0] += 1
        return json.dumps(result, ensure_ascii=False)

    result = call_pat.sub(repl, source)
    print(f"[+] 替换了 {replaced_count[0]} 个代理函数调用")
    return result


# ============================================================
# 6. 主流程
# ============================================================
def deobfuscate(source):
    strings, arr_name = extract_string_array(source)
    if not strings:
        print("[!] 未找到字符串数组 _0x1f85")
        return source

    print(f"[+] 提取到字符串数组: {arr_name}, 共 {len(strings)} 项")

    decoder = Decoder(strings)
    wrappers = parse_wrappers(source)
    result = replace_wrapper_calls(source, wrappers, decoder)
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
