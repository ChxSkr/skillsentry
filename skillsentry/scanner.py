"""SkillSentry 扫描器：遍历 Skill 目录、应用规则、产出结果与判定。"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Iterator

from .rules import RULES, Rule, SEVERITY_ORDER, Severity

# 纳入扫描的文本文件扩展名（未命中时按纯文本尝试读取，跳过明显二进制）
SCAN_EXTENSIONS = {
    ".md", ".txt", ".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs",
    ".ts", ".ps1", ".psm1", ".bat", ".cmd", ".rb", ".pl", ".yaml", ".yml",
    ".json", ".toml", ".ini", ".cfg", ".xml", ".html", ".sql",
}
# 扫描文件大小上限（1MB），避免超大文件拖慢
MAX_FILE_BYTES = 1_000_000
SKIP_DIRS = {".git", ".hg", "node_modules", "__pycache__", ".venv", "venv"}


@dataclass(frozen=True)
class Finding:
    file: str          # 相对路径
    line: int          # 1-based 行号
    rule: Rule
    snippet: str       # 截断后的命中行

    @property
    def severity(self) -> Severity:
        return self.rule.severity

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line,
            "rule_id": self.rule.id,
            "category": self.rule.category,
            "severity": self.rule.severity.value,
            "description": self.rule.description,
            "snippet": self.snippet,
        }


@dataclass
class ScanResult:
    root: str
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        """整体判定：取最严重发现，多个 high 升级为 critical。"""
        sevs = [f.severity for f in self.findings]
        if not sevs:
            return "clean"
        top = max(sevs, key=lambda s: SEVERITY_ORDER[s])
        high_count = sum(1 for s in sevs if s == Severity.HIGH)
        if top == Severity.HIGH and high_count >= 3:
            return Severity.CRITICAL.value
        return top.value

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "files_scanned": self.files_scanned,
            "verdict": self.verdict,
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
        }


def _iter_skill_files(root: str) -> Iterator[str]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            if ext in SCAN_EXTENSIONS or name.upper() == "SKILL.MD":
                yield os.path.join(dirpath, name)


def _read_text(path: str) -> str | None:
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_FILE_BYTES + 1)
        if b"\x00" in data[:4096]:  # 含 NUL 视为二进制，跳过
            return None
        return data.decode("utf-8", errors="replace")
    except OSError:
        return None


def _make_finding(root: str, path: str, lineno: int, line: str, rule: Rule) -> Finding:
    rel = os.path.relpath(path, root).replace(os.sep, "/")
    snippet = line.strip()
    if len(snippet) > 160:
        snippet = snippet[:157] + "..."
    return Finding(file=rel, line=lineno, rule=rule, snippet=snippet)


def scan(root: str, exclude: tuple[str, ...] = ()) -> ScanResult:
    """扫描一个 Skill 目录（或一组目录的父目录）。

    exclude: 相对路径 / glob 模式（fnmatch），命中的文件跳过。
    """
    import fnmatch

    result = ScanResult(root=os.path.abspath(root))
    for path in _iter_skill_files(root):
        rel = os.path.relpath(path, root).replace(os.sep, "/")
        if any(fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(os.path.basename(path), pat)
               for pat in exclude):
            continue
        text = _read_text(path)
        if text is None:
            continue
        result.files_scanned += 1
        is_md = os.path.basename(path).upper() == "SKILL.MD"
        for lineno, line in enumerate(text.splitlines(), start=1):
            for rule in RULES:
                if rule.markdown_only and not is_md:
                    continue
                if rule.pattern.search(line):
                    result.findings.append(_make_finding(root, path, lineno, line, rule))
    result.findings.sort(
        key=lambda f: (f.file, f.line, -SEVERITY_ORDER[f.severity])
    )
    return result


def scan_text(name: str, text: str) -> list[Finding]:
    """对单段文本做规则匹配（供测试与 API 复用）。"""
    is_md = name.upper() == "SKILL.MD"
    out: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for rule in RULES:
            if rule.markdown_only and not is_md:
                continue
            if rule.pattern.search(line):
                out.append(Finding(file=name, line=lineno, rule=rule,
                                   snippet=re.sub(r"\s+", " ", line.strip())[:160]))
    return out
