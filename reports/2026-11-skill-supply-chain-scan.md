# SkillSentry Scan Report #001 — Popular Agent Skill Collections

**Date:** 2026-11-16 · **Tool:** SkillSentry v0.1.0 (static rules, 31 regexes, no LLM) · **Corpus:** 238 skills

## TL;DR

- Scanned **238 skill packages** from three popular collections: `anthropics/skills` (20), `google/skills` (203), `obra/superpowers` (15).
- **205 (86%) verdict CLEAN**; 33 skills flagged (critical: 20, high: 11, medium: 2).
- **Manual review of every CRITICAL finding found zero actual malware.** All were benign context: security reference documents, credential-handling documentation, or defensive instructions.
- One finding was genuinely **review-worthy** (a `exec(base64.b64decode(...))` SSH-exec helper) — legitimate engineering, but exactly the pattern that should require a second look before adoption.
- Conclusion: official collections are healthy. The value of static scanning is **continuous gating and triage**, not one-shot accusation.

## Methodology

1. Cloned three collections (shallow) and enumerated every directory containing a `SKILL.md` — 238 skill roots total.
2. Scanned each skill root with `skillsentry scan <dir> --format json` (31 deterministic rules across 8 risk categories; prompt-injection rules apply only to `SKILL.md`).
3. Aggregated verdicts and findings, then **manually reviewed every CRITICAL/non-EX finding in context**.
4. Rule fixes applied after review: `CR-01` no longer matches `self.env)` / `.env.example`; `OB-01` no longer flags benign `b64decode(...).decode()` or `echo | python3 -c` JSON parsing. Numbers below reflect the **post-fix** scan.

## Verdict distribution

| Verdict | Skills | Share |
|---|---:|---:|
| CLEAN | 205 | 86.1% |
| MEDIUM | 2 | 0.8% |
| HIGH | 11 | 4.6% |
| CRITICAL | 20 | 8.4% |

| Collection | Clean | High | Critical | Medium |
|---|---:|---:|---:|---:|
| `anthropics/skills` | 18 | 1 | 1 | 0 |
| `google/skills` | 174 | 9 | 18 | 2 |
| `obra/superpowers` | 13 | 1 | 1 | 0 |

## Findings by category and rule

Total findings: **249** (critical: 18, high: 222, medium: 9)

| Category | Findings |
|---|---:|
| Data exfiltration (EX) | 169 |
| Privilege escalation (PE) | 26 |
| Persistence (PS) | 25 |
| Credential access (CR) | 14 |
| Command injection (CI) | 9 |
| Prompt injection (PJ) | 3 |
| Destructive ops (DS) | 2 |
| Obfuscated execution (OB) | 1 |

| Top rules | Findings | What it matches |
|---|---:|---|
| `EX-03` | 167 | Network call to a hardcoded external host |
| `PE-01` | 21 | sudo usage |
| `PS-02` | 14 | Write to shell rc / registry Run keys |
| `PS-01` | 11 | crontab / systemd / launchd persistence |
| `CI-01` | 7 | Python eval/exec |
| `CR-02` | 7 | SSH private key access |
| `PE-03` | 5 | sudoers / group modification |
| `CR-03` | 3 | Cloud credential files (~/.aws, ~/.kube, ~/.docker) |
| `PJ-04` | 2 | Execute without user's knowledge |
| `CR-04` | 2 | Browser password/cookie access |
| `DS-03` | 2 | History/log clearing |
| `EX-02` | 2 | File contents piped to network send |
| `CR-05` | 2 | System keychain access |
| `CI-03` | 1 | bash -c indirect execution |
| `PJ-01` | 1 | Hide actions / deceive user |
| `OB-01` | 1 | Decode-then-execute payload |
| `CI-04` | 1 | PowerShell download-and-execute |

## Manual review highlights

### Verified benign (representative examples)

| Finding | Context | Verdict |
|---|---|---|
| `CR-02` SSH key pattern in `anthropics/skills` eval builders | Comments describing a security test fixture (`summary.json -> ~/.ssh/id_rsa`) that must **not** be read | Benign — defensive documentation |
| `CR-03`/`CR-04` in `google/skills` cloud references | Prose explaining AWS/Kube credential resolution and edge token validation | Benign — architecture docs |
| `CR-02` x5 in `google/skills` secops-hunt | Mandiant M-Trends threat-intel tables describing known malware (`QUIETVAULT`, `PROMPTFLUX`) | Benign — security research content |
| `CR-05` keychain in `obra/superpowers` systematic-debugging | `security list-keychains` used to *inspect* keychain state during debugging | Benign — read-only debug step |
| `PJ-04` "without the user's approval" x2 in `google/skills` | Actual text: **"Don't install or update software without the user's approval"** — a *protective* instruction | Benign — negation the regex cannot understand |

### Review-worthy

- `google/skills → cloud/google-cloud-filestore-nfs-browser` (`OB-01`, critical):

  ```python
  # Encode script via base64 to avoid shell quote and escaping issues over SSH
  decoded_expr = f"exec(base64.b64decode('{encoded_script}').decode('utf-8'))"
  remote_cmd = f'python3 -c "import base64; {decoded_expr}"'
  ```

  A jump-host helper that base64-wraps a script for remote `python3 -c` execution. Comment explains the quoting rationale, and the script content is constructed locally — **legitimate**, but this is precisely the decode-then-execute shape that should demand human review before a skill is adopted, because the same shape is how SkillCloak-style payloads hide.

## What this means

1. **Official/curated collections are currently healthy** — no actual malicious skill was found in 238 packages. The risk concentrates in *third-party marketplaces and casual installs*, where research ([ClawHavoc](https://arxiv.org/html/2603.00195v1), [SkillCloak](https://labs.cloudsecurityalliance.org/research/csa-research-note-skillcloak-agent-skill-evasion-20260706-cs/)) already documented 1,200+ malicious skills.
2. **~14% of skills trigger at least one gate** in healthy collections, mostly `EX-03` (calls to hardcoded hosts). For CI gating this is why severity thresholds and allowlists matter more than raw finding counts.
3. **Regex alone cannot judge intent** — negations ("without the user's approval" as a *prohibition*) and research content will always need human triage. SkillSentry's role is to make that triage cheap, ordered, and reproducible.

## Limitations

- Static regex only: packed/self-unpacking payloads that reconstruct at runtime (the SkillCloak technique) are not detected in this version; runtime detonation is on the roadmap.
- Prompt-injection rules are intentionally narrow and English-only; they catch explicit deception instructions, not subtle manipulation.
- This corpus consists of official collections; numbers should not be extrapolated to community marketplaces.

## Reproduce

```bash
git clone --depth 1 https://github.com/anthropics/skills https://github.com/obra/superpowers https://github.com/google/skills
pip install skillsentry  # or: pip install . from a clone
skillsentry scan <skill-dir> --format json
```

Raw findings: [reports/data/scan-2026-11.json](data/scan-2026-11.json)

---

*Generated by [SkillSentry](https://github.com/ChxSkr/skillsentry) — static supply-chain risk scanner for agent skill packages. MIT licensed.*