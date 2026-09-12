#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
jm.py - JS 混淆还原工具 v2
支持：
  1. 提取字符串数组
  2. 复现 _0x3c40 / _0x58b4 的 base64 + RC4 解码
  3. 解析代理函数定义，静态计算调用结果
  4. 替换所有能静态求值的代理函数调用
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
# 2. 复现 _0x3c40 的解码逻辑
# ============================================================
_B64_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/='


def _b64_variant_decode(data):
    """模拟 _0x3bf9ce：自定义 base64 → percent-decode"""
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
    """模拟 _0x4c71ba（RC4 变种）"""
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

    def _0x3c40(self, idx, key):
        """模拟 _0x3c40 的行为"""
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
    找形如：
      function _0x581861(a,b,c,d,e,f,g){
          return _0x58b4(a - -0x15a, g);
      }
    返回：
      { '_0x581861': {'decoder': '_0x58b4', 'idx_arg': 0, 'idx_offset': -0x15a, 'key_arg': 6} }
    """
    wrappers = {}

    # 匹配函数定义
    func_pat = re.compile(
        r'function\s+(_0x[0-9a-fA-F]{4,8})\s*\(([^)]*)\)\s*\{'
        r'\s*return\s+(_0x[0-9a-fA-F]{4,8})\s*\(\s*'
        r'([^,()]+?)\s*,\s*([^()]+?)\s*\)\s*;?\s*\}',
        re.S
    )

    for m in func_pat.finditer(source):
        fn_name = m.group(1)
        params_str = m.group(2)
        decoder = m.group(3)
        idx_expr = m.group(4).strip()
        key_expr = m.group(5).strip()

        if decoder not in ('_0x3c40', '_0x58b4'):
            continue

        params = [p.strip() for p in params_str.split(',') if p.strip()]

        # 解析 idx_expr：形如 `a - -0x15a` 或 `a - 0x28b` 或 `b - - 0x58`
        idx_info = _parse_idx_expr(idx_expr, params)
        if not idx_info:
            continue

        # 解析 key_expr：必须是某个参数名
        if key_expr not in params:
            continue
        key_arg = params.index(key_expr)

        wrappers[fn_name] = {
            'decoder': decoder,
            'idx_arg': idx_info['arg'],
            'idx_offset': idx_info['offset'],
            'key_arg': key_arg,
        }

    return wrappers


def _parse_idx_expr(expr, params):
    """
    解析 `a - -0x15a` / `a - 0x28b` / `a- - 0x58` 这类表达式。
    返回 {'arg': 参数索引, 'offset': 偏移值}
    或 None
    """
    # 去掉空格
    e = expr.replace(' ', '')

    # 匹配 `参数名 - 数字` 或 `参数名 - -数字`
    m = re.match(r'^(\w+)-(-?0x[0-9a-fA-F]+|-?\d+)$', e)
    if not m:
        # 尝试 `数字 - 参数名`（少见）
        return None

    arg_name = m.group(1)
    offset_str = m.group(2)

    if arg_name not in params:
        return None

    try:
        offset = int(offset_str, 0)
    except ValueError:
        return None

    # `a - -0x15a` → a + 0x15a → offset = -(-0x15a) = 0x15a
    # `a - 0x28b` → offset = -0x28b
    # 实际计算时：idx = arg_value - offset
    return {'arg': params.index(arg_name), 'offset': offset}


# ============================================================
# 4. 解析参数值（只支持数字和字符串字面量）
# ============================================================
def _parse_literal(token):
    """解析一个字面量：数字或字符串。失败返回 None。"""
    t = token.strip()

    # 字符串
    m = re.match(r"^'((?:[^'\\]|\\.)*)'$", t)
    if m:
        return m.group(1).replace("\\'", "'").replace('\\\\', '\\')

    m = re.match(r'^"((?:[^"\\]|\\.)*)"$', t)
    if m:
        return m.group(1)

    # 数字（支持十六进制、负号）
    t2 = t.replace(' ', '')
    try:
        return int(t2, 0)
    except ValueError:
        pass

    # 负数
    m = re.match(r'^-(0x[0-9a-fA-F]+|\d+)$', t2)
    if m:
        try:
            return -int(m.group(1), 0)
        except ValueError:
            return None

    return None


# ============================================================
# 5. 替换代理函数调用
# ============================================================
def replace_wrapper_calls(source, wrappers, decoder):
    """
    替换形如 _0x581861(-0xd, ..., 'pdbH') 的调用。
    只替换参数全部是字面量的调用。
    """
    if not wrappers:
        print("[!] 没有解析到代理函数")
        return source

    print(f"[+] 解析到 {len(wrappers)} 个代理函数")

    # 匹配调用：_0xXXXX(args)
    # 注意：要跳过定义（function 后面）
    call_pat = re.compile(
        r'(?<!function\s)'
        r'\b(_0x[0-9a-fA-F]{4,8})\s*\(([^()]*)\)'
    )

    replaced_count = [0]

    def repl(m):
        fn = m.group(1)
        args_str = m.group(2)

        if fn not in wrappers:
            return m.group(0)

        info = wrappers[fn]

        # 按逗号拆分参数（简单处理，不考虑嵌套）
        args = _split_args(args_str)
        if args is None:
            return m.group(0)

        # 解析每个参数为字面量
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

        # 计算真实索引：idx = 参数值 - 偏移
        real_idx = idx_value - info['idx_offset']

        # 解码
        result = decoder._0x3c40(real_idx, key_value)
        if result is None:
            return m.group(0)

        replaced_count[0] += 1
        return json.dumps(result, ensure_ascii=False)

    result = call_pat.sub(repl, source)
    print(f"[+] 替换了 {replaced_count[0]} 个代理函数调用")
    return result


def _split_args(args_str):
    """按逗号拆分参数，跳过空串。返回 None 表示有嵌套无法处理。"""
    if '(' in args_str or '[' in args_str or '{' in args_str:
        return None
    parts = [p.strip() for p in args_str.split(',')]
    return [p for p in parts if p]


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

    # 解析代理函数
    wrappers = parse_wrappers(source)

    # 替换代理函数调用
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
