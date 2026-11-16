"""SkillSentry 静态规则库。

规则按 8 类供应链风险组织，参考 CSA《SkillCloak: Malicious Agent Skills
Evade Marketplace Scanners》的攻击分类。所有规则为确定性正则，
不调用任何模型、零依赖、可复现。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# 各严重级别在判定时的权重（用于排序展示）
SEVERITY_ORDER = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: Severity
    description: str
    pattern: re.Pattern[str]
    # 仅对 SKILL.md 这类指令文件生效的规则（提示注入类）
    markdown_only: bool = False


def _c(pattern: str, flags: int = re.IGNORECASE) -> re.Pattern[str]:
    return re.compile(pattern, flags)


RULES: tuple[Rule, ...] = tuple(
    Rule(
        id=r[0],
        category=r[1],
        severity=r[2],
        description=r[3],
        pattern=_c(r[4]),
        markdown_only=r[5],
    )
    for r in (
        # ---------- 凭据窃取 ----------
        ("CR-01", "credential_theft", Severity.CRITICAL,
         "读取 .env 环境变量文件",
         r"""(?:cat|type|Get-Content|open|read)\s*\(?[^)\n]{0,40}['"]?\.env\b|\.env['"]?\s*\)""",
         False),
        ("CR-02", "credential_theft", Severity.CRITICAL,
         "读取 SSH 私钥",
         r"""(?:cat|Get-Content|open)\s*\(?[^)\n]{0,40}~?/?\.ssh/id_|id_rsa|id_ed25519""",
         False),
        ("CR-03", "credential_theft", Severity.CRITICAL,
         "访问云厂商凭据文件/目录",
         r"""~?/?\.aws/credentials|~?/?\.kube/config|~?/?\.docker/config\.json|AWS_ACCESS_KEY_ID""",
         False),
        ("CR-04", "credential_theft", Severity.CRITICAL,
         "读取浏览器保存的密码/Cookie",
         r"""Login Data|Cookies\b.*(?:sqlite|chrome|edge|firefox)|Web Data|key4\.db|logins\.json""",
         False),
        ("CR-05", "credential_theft", Severity.CRITICAL,
         "访问系统钥匙串/凭据管理器",
         r"""security\s+find-generic-password|cmdkey\s+/list|keychain|secretservice|wincred""",
         False),
        # ---------- 数据外传 ----------
        ("EX-01", "data_exfiltration", Severity.CRITICAL,
         "把环境变量/凭据 POST 到外部地址",
         r"""(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr)[^\n|;]*\s(?:--data|-\w*d|-Body)[^\n]*(?:\$\(?(?:env|ENV|curl|printenv|Get-ChildItem)\b|\$Env:|os\.environ|secrets\.|AWS_|token|password|api[_-]?key)""",
         False),
        ("EX-02", "data_exfiltration", Severity.CRITICAL,
         "把文件内容发送到外部地址",
         r"""(?:curl|wget|Invoke-WebRequest|iwr)\b[^|\n]*\|\s*(?:curl|wget|Invoke-WebRequest|ssh|nc|netcat)\b|(?:curl|wget)\b[^|\n]*(?:--upload-file|-T)\s|fetch\s*\(\s*['"]https?://[^'"]*['"]\s*,\s*\{[^}]*body\s*:""",
         False),
        ("EX-03", "data_exfiltration", Severity.HIGH,
         "向硬编码外部主机发起网络外联",
         r"""(?:curl|wget|requests\.(?:get|post)|urllib\.request\.urlopen|fetch\s*\()\s*\(?\s*['"]https?://(?:\d{1,3}\.){3}\d{1,3}|(?:webhook|pastebin|ngrok|transfer\.sh|file\.io|0x0\.st)""",
         False),
        ("EX-04", "data_exfiltration", Severity.HIGH,
         "通过 DNS/ICMP 隧道外传数据（编码查询）",
         r"""nslookup\s+\S{60,}\.|dig\s+\+short\s+\S{60,}\.|(?:ping|nslookup)\s+`[^`]{40,}`""",
         False),
        # ---------- 命令执行 ----------
        ("CI-01", "command_injection", Severity.HIGH,
         "Python 动态代码执行 eval/exec",
         r"""(?:^|\s|;)(?:eval|exec)\s*\(""",
         False),
        ("CI-02", "command_injection", Severity.HIGH,
         "带 shell 解释器的子进程调用",
         r"""subprocess\.\w+\([^)\n]*shell\s*=\s*True|os\.system\s*\(|child_process\.exec(?:Sync)?\s*\(|shelljs\.exec""",
         False),
        ("CI-03", "command_injection", Severity.MEDIUM,
         "bash -c / sh -c 间接执行",
         r"""\b(?:ba)?sh\s+-c\s+['"]""",
         False),
        ("CI-04", "command_injection", Severity.MEDIUM,
         "PowerShell 下载并执行",
         r"""Invoke-Expression\s*\(?|\bIEX\b|DownloadString|DownloadFile.*invoke|-EncodedCommand""",
         False),
        # ---------- 混淆执行 ----------
        ("OB-01", "obfuscated_execution", Severity.CRITICAL,
         "解码后直接送入 shell/解释器执行",
         r"""(?:echo\s+\S+|base64\s+-d|certutil\s+-decode|FromBase64String)[^\n|;]{0,80}\|\s*(?:ba)?sh\b|(?:echo|cat)\b[^|\n]*\|\s*python3?\b|b64decode[^)\n]{0,60}\)?\s*(?:\.decode|exec|eval)|exec\s*\(\s*base64""",
         False),
        ("OB-02", "obfuscated_execution", Severity.CRITICAL,
         "解码十六进制/ROT13 等编码后执行",
         r"""(?:fromhex|codecs\.decode|rot13|chr\(\d+\)\s*for)[^\n]{0,80}(?:exec|eval|subprocess|os\.system)""",
         False),
        ("OB-03", "obfuscated_execution", Severity.HIGH,
         "超长 base64/十六进制字面量（疑似内嵌载荷）",
         r"""['"][A-Za-z0-9+/=]{300,}['"]|\b(?:[0-9a-fA-F]{2}){120,}\b""",
         False),
        ("OB-04", "obfuscated_execution", Severity.HIGH,
         "自解压/自安装二进制载荷",
         r"""(?:xz\s+-d|gzip\s+-d|tar\s+xz?f?)\s*[^|\n]*\|\s*(?:ba)?sh\b|pigz\s+-d""",
         False),
        # ---------- 提权 ----------
        ("PE-01", "privilege_escalation", Severity.HIGH,
         "使用 sudo 执行命令",
         r"""\bsudo\s+(?!-l\b|apt(?:-get)?\s+update|yum\s+makecache)""",
         False),
        ("PE-02", "privilege_escalation", Severity.HIGH,
         "修改文件为任意用户可写/可执行",
         r"""chmod\s+(?:777|666|\+s|u\+s|setuid)|icacls\s+[^ ]+\s*/grant\s+.{0,30}:\s*F""",
         False),
        ("PE-03", "privilege_escalation", Severity.MEDIUM,
         "尝试修改系统账户/计划任务权限",
         r"""/etc/sudoers|usermod\s+-[aG]|net\s+localgroup\s+administrators""",
         False),
        # ---------- 持久化 ----------
        ("PS-01", "persistence", Severity.HIGH,
         "写入 crontab / systemd / launchd 实现持久化",
         r"""crontab\s+[-lwe]|systemctl\s+enable|/etc/systemd/system/|launchctl\s+(?:load|submit)|\.plist\b""",
         False),
        ("PS-02", "persistence", Severity.HIGH,
         "写入注册表启动项 / shell 配置实现持久化",
         r"""CurrentVersion\\Run|\.bashrc|\.zshrc|\.profile['"]?\s*$|profile\.ps1|powershell\s+-Command.*Get-ItemProperty.*Run""",
         False),
        ("PS-03", "persistence", Severity.MEDIUM,
         "安装自启动代理/服务",
         r"""LaunchAgents|Startup\s+Folder|schtasks\s+/create|sc\s+create\s""",
         False),
        # ---------- 破坏性操作 ----------
        ("DS-01", "destructive_ops", Severity.CRITICAL,
         "递归删除根目录/大范围文件",
         r"""rm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+(?:(/|~|\*|\$HOME|C:\\)\s*$|/(?!\w)|~\s*$|\*)""",
         False),
        ("DS-02", "destructive_ops", Severity.CRITICAL,
         "向物理磁盘写入原始数据（dd/format）",
         r"""dd\s+[^|\n]*of=/dev/(?:sd|nvme|disk)|format\s+[a-zA-Z]:|Remove-Item\s+-Recurse\s+-Force\s+(?:C:\\|\$home|\~)""",
         False),
        ("DS-03", "destructive_ops", Severity.HIGH,
         "清空历史/日志以抹除痕迹",
         r"""(?:shred|>|:)\s*/(?:var/log|var\/log)|history\s+-c|Clear-History|wevtutil\s+cl|rm\s+-[rf]+\s+/var/log""",
         False),
        # ---------- 提示注入（仅 SKILL.md） ----------
        ("PJ-01", "prompt_injection", Severity.CRITICAL,
         "指示 Agent 隐瞒行为/欺骗用户",
         r"""do\s+not\s+(?:tell|inform|disclose|reveal)\s+(?:the\s+)?user|don'?t\s+(?:tell|inform)\s+the\s+user|hide\s+(?:this|these)\s+(?:instructions|actions)|keep\s+(?:this|it)\s+(?:secret|hidden)""",
         True),
        ("PJ-02", "prompt_injection", Severity.CRITICAL,
         "要求 Agent 忽略安全指令/系统提示",
         r"""ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|disregard\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions)|override\s+(?:your|the)\s+(?:safety|system)""",
         True),
        ("PJ-03", "prompt_injection", Severity.HIGH,
         "要求把对话/文件内容上传到外部",
         r"""(?:upload|send|post|exfiltrate)\s+(?:the\s+)?(?:conversation|chat|files?|contents?)\s+to\s+(?:a\s+)?(?:remote|external|attacker|my)\b""",
         True),
        ("PJ-04", "prompt_injection", Severity.MEDIUM,
         "要求在用户不知情时执行",
         r"""without\s+(?:the\s+)?user'?s?\s+(?:knowledge|consent|approval)|silently\s+(?:run|execute|install)""",
         True),
    )
)


def iter_rules() -> tuple[Rule, ...]:
    return RULES
