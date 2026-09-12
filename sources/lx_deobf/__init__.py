"""LX 音源反混淆预处理包。"""

from .preprocess import deobfuscate_file, is_obfuscated

__all__ = ["deobfuscate_file", "is_obfuscated"]
