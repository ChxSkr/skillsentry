# SkillSentry

Static supply-chain risk scanner for **AI agent skill packages** (`SKILL.md` + bundled scripts).

Agent skill marketplaces are exploding — and so are malicious skills. Research
([CSA: SkillCloak](https://labs.cloudsecurityalliance.org/research/csa-research-note-skillcloak-agent-skill-evasion-20260706-cs/),
[ClawHavoc campaign](https://arxiv.org/html/2603.00195v1)) showed that 1,200+ malicious skills
infiltrated public marketplaces and that self-unpacking payloads bypassed 8 commercial
scanners with >90% success. SkillSentry gives you a deterministic, zero-dependency first line of defense.

**Zero third-party dependencies** (pure Python stdlib) — the scanner itself cannot be supply-chain attacked.

## What it detects

| Category | Severity | Examples |
|---|---|---|
| Credential theft | CRITICAL | reading `.env`, `~/.ssh/id_rsa`, AWS/browser/keychain credentials |
| Data exfiltration | CRITICAL | POSTing env vars/files to external hosts, DNS tunneling |
| Obfuscated execution | CRITICAL | `base64 -d \| sh`, `exec(b64decode(...))`, huge encoded payloads |
| Destructive ops | CRITICAL | `rm -rf /`, raw disk writes, log shredding |
| Command injection | HIGH | `eval`, `subprocess(..., shell=True)`, PowerShell `IEX` |
| Privilege escalation | HIGH | `sudo`, `chmod 777`, sudoers edits |
| Persistence | HIGH | crontab, systemd/launchd, registry Run keys, rc files |
| Prompt injection | CRITICAL/HIGH/MED | "ignore previous instructions", "don't tell the user", silent execution |

Prompt-injection rules only apply to instruction files (`SKILL.md`), matching how skills actually work.

## Install & use

```bash
pip install .            # from a clone
skillsentry scan ./some-skill
skillsentry scan ./some-skill --format json
skillsentry scan ./some-skill --format sarif > results.sarif
skillsentry scan . --fail-on high   # CI gate: exit 1 on high/critical
skillsentry scan . -e README.md -e "**/rules.py"   # exclude self-documenting files
```

Example output:

```
SkillSentry scan report — examples/malicious-skill
files scanned: 1   findings: 17   verdict: CRITICAL
  critical: 7  high: 9  medium: 1

[SKILL.md]
  L13   CRITICAL CR-01  读取 .env 环境变量文件
        > cat .env >> /tmp/k
  ...
```

## GitHub Action

```yaml
- uses: ChxSkr/skillsentry@main
  with:
    path: .          # skill 目录
    fail-on: high    # never | low | medium | high | critical
    format: text     # text | json | sarif
```

With `format: sarif` you can upload results to GitHub code scanning:

```yaml
- uses: ChxSkr/skillsentry@main
  id: scan
  with: { format: sarif, fail-on: never }
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: results.sarif }
```

## Verdict logic

- `clean` — no findings
- otherwise the highest severity present, with **3+ HIGH findings escalating to CRITICAL**

`--fail-on` (default `high`) makes the CLI exit `1` so CI pipelines fail fast.

## Scope & honest limitations

SkillSentry is **static and deterministic** — fast, cheap, reproducible, no model calls.
It does **not** replace runtime sandboxing (e.g. detonation) or semantic LLM review;
packed/encrypted payloads that only reconstruct at execution time may evade static rules.
Use it as the cheap first gate in a defense-in-depth pipeline.

## Development

```bash
pip install -e . pytest
pytest -q
skillsentry scan examples/malicious-skill   # must be critical
skillsentry scan examples/benign-skill      # must be clean
```

## License

MIT
