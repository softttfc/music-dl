"""Pure-Python adapter for LX Music JS sources.
支持混淆源：解析前自动调用反混淆预处理。
"""

import re
import json
from pathlib import Path
from typing import Optional, List, Dict

import requests

from sources.base import MusicSource, SearchResult

try:
    from sources.lx_deobf.preprocess import deobfuscate_file, is_obfuscated
except ImportError:
    deobfuscate_file = None

    def is_obfuscated(source: str) -> bool:
        return False


class LxMusicSource(MusicSource):
    """Wraps a LX Music JS source, with deobfuscation preprocessing."""

    _HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    }

    def __init__(self, source_path: str, auto_deobf: bool = True):
        self.source_path = source_path
        self._raw = ""
        self._deobf_path: Optional[str] = None
        self._name = Path(source_path).stem
        self._platforms: Dict[str, dict] = {}
        self._url_templates: Dict[str, dict] = {}
        self._parse(source_path, auto_deobf)

    @property
    def name(self) -> str:
        return "lx_" + self._name

    # ============================================================
    # 1. 解析入口
    # ============================================================
    def _parse(self, path: str, auto_deobf: bool = True):
        try:
            with open(path, encoding="utf-8") as f:
                raw = f.read()
        except Exception as e:
            print(f"[lx_adapter] 读取失败: {e}")
            return

        # ---- 反混淆预处理 ----
        if auto_deobf and deobfuscate_file is not None and is_obfuscated(raw):
            try:
                self._deobf_path = deobfuscate_file(path)
                with open(self._deobf_path, encoding="utf-8") as f:
                    raw = f.read()
                print(f"[lx_adapter] 已反混淆: {self._deobf_path}")
            except Exception as e:
                print(f"[lx_adapter] 反混淆失败，使用原文件: {e}")

        self._raw = raw

        m = re.search(r'@name\s+(.+)', self._raw)
        if m:
            self._name = m.group(1).strip()

        self._parse_sources(self._raw)
        self._parse_urls(self._raw)

    # ============================================================
    # 2. 解析 sources
    # ============================================================
    def _parse_sources(self, source: str):
        for kw in ("sources", "source", "音源"):
            idx = source.find(kw)
            if idx == -1:
                continue
            brace_start = source.find("{", idx)
            if brace_start == -1:
                continue
            block = self._extract_balanced(source, brace_start)
            if not block:
                continue
            self._parse_platform_blocks(block)
            if self._platforms:
                return

    def _extract_balanced(self, s: str, start: int) -> Optional[str]:
        if start >= len(s) or s[start] != "{":
            return None
        depth = 0
        in_str = None
        i = start
        while i < len(s):
            ch = s[i]
            if in_str:
                if ch == "\\":
                    i += 2
                    continue
                if ch == in_str:
                    in_str = None
            else:
                if ch in ("'", '"', "`"):
                    in_str = ch
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        return s[start:i + 1]
            i += 1
        return None

    def _parse_platform_blocks(self, block: str):
        i = 0
        n = len(block)
        while i < n:
            m = re.match(r"\s*['\"]?(\w+)['\"]?\s*:", block[i:])
            if not m:
                i += 1
                continue
            key = m.group(1)
            colon_end = i + m.end()
            brace_start = block.find("{", colon_end)
            if brace_start == -1:
                break
            between = block[colon_end:brace_start].strip(" \t\r\n,")
            if between:
                i = colon_end
                continue
            val = self._extract_balanced(block, brace_start)
            if not val:
                break
            self._register_platform(key, val)
            i = brace_start + len(val)

    def _register_platform(self, key: str, block: str):
        if key in ("local",):
            return
        info: dict = {"key": key}
        for field, pattern in [
            ("name", r"name\s*:\s*['\"]([^'\"]+)['\"]"),
            ("type", r"type\s*:\s*['\"]([^'\"]+)['\"]"),
        ]:
            fm = re.search(pattern, block)
            if fm:
                info[field] = fm.group(1)
        actions_m = re.search(r"actions\s*:\s*\[([^\]]+)\]", block)
        if actions_m:
            info["actions"] = [a.strip().strip("'\"") for a in actions_m.group(1).split(",")]
        qual_m = re.search(r"qualitys\s*:\s*\[([^\]]+)\]", block)
        if qual_m:
            info["qualitys"] = [q.strip().strip("'\"") for q in qual_m.group(1).split(",")]
        if info.get("name"):
            self._platforms[key] = info

    # ============================================================
    # 3. URL 模板
    # ============================================================
    def _parse_urls(self, source: str):
        for m in re.finditer(
            r'(?:lx\.request|httpFetch|request)\s*\(\s*[`\'"]([^`\'"]+)[`\'"]',
            source,
        ):
            self._register_url_template(m.group(1))

        for m in re.finditer(
            r'[`\'"](https?://[^\s`\'"]*\$\{[^}]+}[^\s`\'"]*)[`\'"]',
            source,
        ):
            self._register_url_template(m.group(1))

        for m in re.finditer(r'[`\'"](https?://[^\s`\'"]+)[`\'"]', source):
            self._register_url_template(m.group(1))

        for key in self._platforms:
            self._url_templates.setdefault(key, {"urls": []})

    def _register_url_template(self, url: str):
        if not url or "http" not in url:
            return
        assigned = False
        for key in self._platforms:
            if key in url:
                self._url_templates.setdefault(key, {"urls": []})
                self._url_templates[key]["urls"].append(url)
                assigned = True
        if not assigned:
            self._url_templates.setdefault("_generic", {"urls": []})
            self._url_templates["_generic"]["urls"].append(url)

    # ============================================================
    # 4. 搜索
    # ============================================================
    def search(self, title: str, artist: str = "") -> List[SearchResult]:
        results = []
        query = f"{title} {artist}".strip()

        for key in self._platforms:
            search_urls = self._find_search_urls(key, query)
            for url in search_urls:
                try:
                    resp = requests.get(url, headers=self._HEADERS, timeout=10)
                    data = resp.json()
                    songs = self._extract_songs(data, key)
                    for s in songs[:3]:
                        results.append(SearchResult(
                            title=s.get("title", s.get("name", "")),
                            artist=s.get("artist", s.get("singer", "")),
                            download_url=s.get("url", ""),
                            duration=s.get("duration", 0),
                            free=True,
                            match_score=0.4,
                        ))
                except Exception:
                    continue
        return results

    def _find_search_urls(self, platform: str, query: str) -> List[str]:
        urls = []
        for url in self._url_templates.get(platform, {}).get("urls", []):
            if "search" not in url.lower() and "关键词" not in url:
                continue
            urls.append(self._fill_placeholders(url, query))
        if not urls:
            for url in self._url_templates.get("_generic", {}).get("urls", []):
                if "search" in url.lower():
                    urls.append(self._fill_placeholders(url, query))
        return urls[:2]

    def _fill_placeholders(self, url: str, query: str) -> str:
        replacements = {
            "${keyword}": query, "${key}": query, "${word}": query,
            "${query}": query, "${w}": query,
            "${page}": "1", "${limit}": "30", "${num}": "30",
        }
        for k, v in replacements.items():
            url = url.replace(k, v)
        return url

    def _extract_songs(self, data, platform: str) -> List[dict]:
        songs = []
        for path in [
            "data.list", "data.info", "data.songs", "result.songs",
            "data", "songList", "list", "data.songList", "result.list",
        ]:
            node = data
            for k in path.split("."):
                if isinstance(node, dict):
                    node = node.get(k, {})
                else:
                    break
            if isinstance(node, list) and node:
                songs = node
                break
        if not songs and isinstance(data, list):
            songs = data
        return songs[:10]

    def get_download_url(self, song_id: str) -> Optional[str]:
        if song_id and song_id.startswith("http"):
            return song_id
        return None

    def get_platforms(self) -> List[str]:
        return list(self._platforms.keys())
