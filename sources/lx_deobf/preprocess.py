"""反混淆预处理：调用 Node 运行时 hook + Python 静态反混淆。"""

import os
import re
import sys
import shutil
import subprocess
from pathlib import Path
from typing import Optional


def is_obfuscated(source: str) -> bool:
    """判断 JS 是否被混淆。"""
    if re.search(r"function\s+_0x[0-9a-f]{4,8}\s*\(", source):
        return True
    if "_0x1f85" in source or "_0x3c40" in source:
        return True
    if re.search(r"parseInt\([^)]+\)\s*/\s*0x", source):
        return True
    return False


def _find_node() -> Optional[str]:
    return shutil.which("node")


def _find_deobfuscator() -> Optional[str]:
    return shutil.which("deobfuscator")


def deobfuscate_file(src_path: str, out_dir: Optional[str] = None) -> str:
    """
    对单个 JS 文件做反混淆，返回反混淆后的文件路径。
    流程：
      1. runtime_hook.js → runtime-dump.json
      2. jm.py → deobf.js
      3. deobfuscator（可选）→ deobf-final.js
    """
    src = Path(src_path).resolve()
    if not src.exists():
        raise FileNotFoundError(f"源文件不存在: {src}")

    out_dir = Path(out_dir or src.parent / "deobf_cache")
    out_dir.mkdir(parents=True, exist_ok=True)

    # 缓存 key：文件名 + mtime
    cache_key = f"{src.stem}_{src.stat().st_mtime_ns}"
    final_out = out_dir / f"{cache_key}.deobf.js"
    if final_out.exists():
        print(f"[preprocess] 命中缓存: {final_out}")
        return str(final_out)

    here = Path(__file__).parent
    runtime_hook = here / "runtime_hook.js"
    jm_py = here / "jm.py"

    dump_path = out_dir / f"{cache_key}.runtime-dump.json"
    step1_out = out_dir / f"{cache_key}.deobf.step1.js"

    # ---- 1. 运行时 hook ----
    node = _find_node()
    if node and runtime_hook.exists():
        try:
            subprocess.run(
                [node, str(runtime_hook), str(src), str(dump_path)],
                check=True, timeout=60,
                capture_output=True, text=True,
            )
            print(f"[preprocess] runtime hook 完成: {dump_path}")
        except subprocess.CalledProcessError as e:
            print(f"[preprocess] runtime hook 失败: {e.stderr[:300]}")
            dump_path = None
        except Exception as e:
            print(f"[preprocess] runtime hook 异常: {e}")
            dump_path = None
    else:
        print("[preprocess] 未找到 node，跳过 runtime hook")
        dump_path = None

    # ---- 2. jm.py ----
    cmd = [sys.executable, str(jm_py), str(src), str(step1_out)]
    if dump_path and dump_path.exists():
        cmd.append(str(dump_path))
    try:
        subprocess.run(cmd, check=True, timeout=60, capture_output=True, text=True)
        print(f"[preprocess] jm.py 完成: {step1_out}")
    except Exception as e:
        print(f"[preprocess] jm.py 失败: {e}")
        shutil.copy(src, step1_out)

    # ---- 3. deobfuscator（可选） ----
    deob = _find_deobfuscator()
    if deob:
        try:
            subprocess.run(
                [deob, str(step1_out), "-o", str(final_out)],
                check=True, timeout=120,
                capture_output=True, text=True,
            )
            print(f"[preprocess] deobfuscator 完成: {final_out}")
            return str(final_out)
        except Exception as e:
            print(f"[preprocess] deobfuscator 失败: {e}")

    shutil.copy(step1_out, final_out)
    return str(final_out)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python preprocess.py 原文件.js [输出目录]")
        sys.exit(1)
    out = deobfuscate_file(sys.argv[1], sys.argv[2] if len(sys.argv) >= 3 else None)
    print(f"[+] 最终输出: {out}")
