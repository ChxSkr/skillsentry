"""结果渲染：文本 / JSON / SARIF 三种输出格式。"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .scanner import ScanResult

# SARIF 级别映射
_SARIF_LEVEL = {"critical": "error", "high": "error",
                "medium": "warning", "low": "note"}


def render_text(result: ScanResult) -> str:
    lines: list[str] = []
    counts = result.summary()
    lines.append(f"SkillSentry scan report — {result.root}")
    lines.append(f"files scanned: {result.files_scanned}   "
                 f"findings: {len(result.findings)}   verdict: {result.verdict.upper()}")
    if counts:
        lines.append("  " + "  ".join(f"{k}: {v}" for k, v in sorted(counts.items())))
    lines.append("")
    cur_file = None
    for f in result.findings:
        if f.file != cur_file:
            cur_file = f.file
            lines.append(f"[{cur_file}]")
        lines.append(f"  L{f.line:<4} {f.severity.value.upper():<8} "
                     f"{f.rule.id}  {f.rule.description}")
        lines.append(f"        > {f.snippet}")
    if not result.findings:
        lines.append("No supply-chain risk patterns detected.")
    return "\n".join(lines)


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), ensure_ascii=False, indent=2)


def render_sarif(result: ScanResult) -> str:
    rules = {f.rule.id: f.rule for f in result.findings}
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "SkillSentry",
                "informationUri": "https://github.com/ChxSkr/skillsentry",
                "rules": [
                    {"id": r.id,
                     "shortDescription": {"text": r.description},
                     "properties": {"category": r.category,
                                    "security-severity": _semver_sev(r.severity)}}
                    for r in rules.values()
                ],
            }},
            "results": [
                {"ruleId": f.rule.id,
                 "level": _SARIF_LEVEL[f.severity.value],
                 "message": {"text": f"{f.rule.description}: {f.snippet}"},
                 "locations": [{"physicalLocation": {
                     "artifactLocation": {"uri": f.file},
                     "region": {"startLine": f.line}}}]}
                for f in result.findings
            ],
            "originalUriBaseIds": [{
                "description": {"text": f"scan root: {result.root}"},
            }],
            **{"automationDetails": {"id": f"skillsentry/{datetime.now(timezone.utc):%Y%m%d%H%M%S}"}},
        }],
    }
    return json.dumps(sarif, ensure_ascii=False, indent=2)


def _semver_sev(sev) -> str:
    # GitHub code scanning 使用 0-10 的 security-severity
    return {"critical": "9.5", "high": "8.0",
            "medium": "5.0", "low": "2.0"}[sev.value]
