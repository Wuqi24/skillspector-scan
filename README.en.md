[English](README.en.md) | [简体中文](README.md)

# skillspector-scan

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Release](https://img.shields.io/github/v/release/Wuqi24/skillspector-scan)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE)
![GitHub stars](https://img.shields.io/github/stars/Wuqi24/skillspector-scan?style=social)
![GitHub last commit](https://img.shields.io/github/last-commit/Wuqi24/skillspector-scan)

**Audit AI agent skills individually.**

An offline, evidence-driven, auditable static security scanner for AI agent skills (Codex skills). It reviews local skills one by one and detects 16+ risk categories — prompt injection, data exfiltration, supply-chain, dangerous code calls, and more — producing easy-to-read security reports. The minimal audit unit is a **single skill**: 1 skill → 1 Target → 1 Scan Result → 1 review decision. It never installs or executes any script from the target skill; risk labels are automatic inference, not a substitute for human review.

## What It Is

`skillspector-scan` is a static security review skill that runs inside the Codex skill system, and also ships a standalone script `scripts/scan.ps1` for local review before installing third-party skills.

Covered risk categories (detailed checks in [references/checklist.md](references/checklist.md)):

- Instructions & behavior: prompt injection, refusal-evasion/jailbreak, system prompt leakage, memory poisoning, excessive autonomy, trigger-word abuse, untrusted external instruction sources (OWASP AST05)
- Data & network: data exfiltration, tainted outbound transfer, SSRF (cloud metadata / internal network / loopback), agent spying
- Code & supply-chain: unpinned versions, remote scripts, obfuscation, known vulnerabilities, look-alike packages, dangerous calls (exec/eval/subprocess), privilege escalation, persistence, tool abuse
- Metadata & ecosystem: manifest consistency, symlink escape, MCP least-privilege / tool poisoning, known malware signatures (webshell / cryptominer / reverse shell), manifest changes (rug-pull)

## Features

- Fully offline: the only optional network feature is `-CheckCVE` (OSV.dev lookup, auto-degrades to offline on failure)
- Skill granularity: a skill is the minimal audit unit; `-Path` pointing to a repo/collection auto-detects skill roots (SKILL.md) and splits per skill; plain directories are still scanned but flagged as "not recognized as an isolated skill"
- Static read-only: no sandbox, no auto-block, no auto-sanitization
- Per-file single read + multi-stage specialized checks + encoding detection (UTF-8/UTF-16/GBK) + context annotation + comment-aware lexical analysis
- Python AST/lightweight taint analysis, JS behavior heuristics, base64 payload decode re-check, symlink escape detection, git-history secret detection, manifest-change detection
- Dependency pinning and offline dependency analysis (source allowlist, typo-squatting, install-script hooks, dependency-count thresholds)
- Brief mode (`-Brief`): behavior summary → worst-case TOP3 → detailed findings → reference findings → dependency risks; every hit includes "fact + inference"
- Verified records (`-MarkVerified`): file SHA-256 manifest + conclusion + date; content changes automatically invalidate conclusions
- Inspection Ledger (Phase 4B): `audit.inspection_run_id` + `inspection[]` (engine lifecycle + frozen reason_code), a side-channel record that never changes scoring/evidence
- Pre-publish gate (`-PrePublish`): blacklisted files (.env/secret files) + content that looks like secrets + git-history secrets; warn-only, not blocking. Known expectation: content checks flag fake test secrets in `scripts/test.ps1` (e.g., `sk-prepubtest...`) — expected; confirm the masked value is test data before release
- Optional external scanner adapters: auto-invokes `aguara` / `skill-scanner` when detected and merges hits (`EXT_AGUARA` / `EXT_SKILLSCANNER`); SKIP (not error) when missing; `-NoExt` disables
- JSON reports include `engines` checker status (regex/multi/lexer/python_ast/js/deps/osv/git_history/manifest/external_*, on/skipped/disabled/degraded)
- JSON output (`-Json`), batch (`-AllInstalled`/`-Dir`), parallel (`-Parallel`), baseline false-positive suppression (`-Baseline`), dependency checks (`-CheckDeps`)

## Installation

```powershell
# 1. Clone directly into the Codex skills directory (repo name = skill name)
git clone https://github.com/Wuqi24/skillspector-scan.git "$HOME\.codex\skills\skillspector-scan"

# 2. Or download the release package skillspector-scan-vX.Y.Z.zip from GitHub Releases
#    (no test fixtures / CI files) and extract it to "$HOME\.codex\skills\skillspector-scan"
#    (the zip top level is the skill directory)

# 3. Can also be used as a standalone script without Codex (after entering the skill directory)
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/scan.ps1 -Path <skill-directory>
```

Dependencies: PowerShell 5.1+ (7 recommended). Python optional: used for AST/taint analysis; when missing it auto-degrades to regex and marks the report; use `-Python <path>` to specify, `-NoAst` to disable.

## Usage

**Path semantics**: `-Path` is interpreted as a single skill first (SKILL.md detected → outputs `Target Type: skill`); pointing to a repo/category containing multiple skills auto-splits into independent skill Targets (with a Warning; `-Interactive` lets you choose first); plain directories are still scanned but flagged `not recognized as isolated skill`. `-Dir` = scan multiple skills in a directory; `-AllInstalled` = review all installed skills one by one (recommended entry point).

```powershell
# Basic scan (text report; exit code 0 ok / 1 target >50 points / 2 error)
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/scan.ps1 -Path <skill-directory>

# Scan all installed skills (excludes .system)
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/scan.ps1 -AllInstalled

# Batch scan uninstalled skills (each subdir/zip counts as a target; add -Parallel)
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/scan.ps1 -Dir <skills-folder>

# Brief mode (facts / inference two-part report)
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/scan.ps1 -Path <skill-directory> -Brief

# JSON output (CI-friendly)
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/scan.ps1 -Path <skill-directory> -Json -Output report.json

# Write a verified record after human review (full scan only; writes to skill root .verified/; honors CODEX_HOME, falls back to ~/.codex/skills/.verified/)
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/scan.ps1 -MarkVerified allow -Path <skill-directory>

# Pre-publish gate (blacklisted files + content-looking secrets + git history; exit 0=pass / 1=risk / 2=argument error)
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/scan.ps1 -Path <release-source-directory> -PrePublish
# Note: content checks flag fake test secrets in scripts/test.ps1 (e.g., sk-prepubtest...) — expected; confirm masked values are test data before release

# Baseline suppression of false positives
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/scan.ps1 -Path <skill-directory> -InitBaseline

# Optional: check pinned dependencies for known vulnerabilities online (OSV.dev; auto-degrades offline)
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/scan.ps1 -Path <skill-directory> -CheckCVE

# Optional: scan git history for secrets that appeared in recent commits
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/scan.ps1 -Path <skill-directory> -GitHistory

# Check checker availability (Python/git/aguara/skill-scanner/registry; no scan)
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/scan.ps1 -CheckDeps
```

In PowerShell 7, replace the leading `powershell` with `pwsh`. Scanning `.zip` directly is supported (with member count and total extraction size limits to prevent zip bombs).

## Cloud CI Scanning (no local environment)

This repo provides a reusable GitHub Actions workflow: put any skill into any GitHub repository to scan it in the cloud — no local PowerShell / Python / git install required.

**Reference from another repository (recommended)**

Add a workflow in the target repository (e.g., `.github/workflows/scan-skill.yml`):

```yaml
name: scan-skill
on: workflow_dispatch
jobs:
  scan:
    permissions:
      contents: read
    uses: Wuqi24/skillspector-scan/.github/workflows/skill-scan.yml@main
    with:
      skill_path: '.'      # skill path to scan (relative to target repo root)
      mode: prepublish     # prepublish=pre-release gate; full=full risk scan
```

Parameters:

| Parameter | Default | Description |
|:---|:---|:---|
| `skill_path` | `.` | Skill/directory path to scan (relative to target repo root) |
| `mode` | `prepublish` | `prepublish`=pre-release gate (blacklisted files + content + git-history secrets); `full`=full risk scan |

- The report is uploaded as artifact `skillspector-report` (downloadable from the Actions run page)
- In `prepublish`, the job fails when risks are found (exit 1), acting as a release gate
- If the target skill contains fake test secrets, `prepublish` flags them (expected); `full` is for ordinary risk scans

**This repository itself**

- Manual: Actions page → `skillspector-scan` → Run workflow (optional self-check / full regression / Docker build verification)
- Release: pushing a `v*` tag auto-runs self-check + full regression + Docker build with malicious fixture verification

## Rule Registry

Detection rules are a **frozen rule registry** [rules/rules.yaml](rules/rules.yaml), fixed after human review:

- 36 unique detection/correlation rules (40 registry entries total, of which YRM multi-line malware signatures are 5 regex rules)
- 4 helper hints (not counted as risks)
- 11 brief-mode display projections

Normal mode and brief mode share the same rule source: the engine loads one registry; brief mode projects normal rule hits into more specific brief rules via `briefProjectionFrom` (e.g., E2 → SECRET_ENV_READ). No online updates, no runtime ingestion (the poison-library design was removed); changing a rule changes `rules_hash`, auto-invalidating old verified records, which must be re-reviewed.

## Decision Policy

`data/policy.yaml` is an independent decision-policy layer: it only maps `severity/risk facts → decision_recommendation` (defaults: LOW→ALLOW, MEDIUM→REVIEW, HIGH/CRITICAL→BLOCK) and **contains no analyzer rules, regex, evidence generation, or score algorithms**.

- Outputs `target.decision_recommendation`: a machine-consumable enum suggestion (ALLOW / REVIEW / BLOCK); never modifies score / severity / finding / evidence / ranking
- Display projection (Phase 6B): normal CLI and Brief outputs add a "Decision Recommendation" line that reads the result directly without a second judgment; multi-target brief summaries aggregate by policy (BLOCK > REVIEW > ALLOW) — display only, single-target decisions unchanged
- `target.decision_reason[]`: generated from the same source as the decision (`severity=<SEVERITY>`, `policy_rule=<SEVERITY>_TO_<DECISION>`), auditable "why this suggestion"
- `policy_hash` (canonical yaml → SHA-256) enters audit, inspection ledger, verified, and baseline; policy changes auto-invalidate old audit records
- Human review: `-MarkVerified allow|deny -Reviewer <name>` records the reviewer; defaults to `anonymous`

## Verified Records

- Location: skill root `.verified/<skill>.json` (honors `CODEX_HOME`, falls back to `~/.codex/skills/.verified/`)
- Written only explicitly via `-MarkVerified allow|deny -Path <skill>`; scans never write to disk
- Prerequisite: target `analysis_status` must be `complete`, otherwise writes are forbidden
- Rescan is read-only comparison: all file SHA-256 match → "previously verified"; any change → "content changed, previous conclusion may be invalid"; rule/config version or hash changed → "scan rules or config updated, previous conclusion may be invalid"
- Result fingerprint binding (Phase 7A): records also store `finding_fingerprint` / `evidence_fingerprint` (aggregated hash of risk Finding IDs and their referenced Evidence IDs); identical input+environment but different result → "scanner behavior or rule interpretation changed, previous conclusion may be invalid"; old records without fingerprints → "recommend re-review", never pretend to be valid
- Policy binding (Phase 6A): `policy_hash` change → old records show invalidation hints; records include `reviewer`
- Display-only folding; never auto-blocks

## Baseline

- `-InitBaseline` writes a false-positive suppression list; `-Baseline <file>` suppresses previously reviewed findings on rescan; `-ShowSuppressed` views them
- Baseline files record `scanner_hash` / `rules_hash` / `policy_hash`: on any version mismatch, old suppressions are **disabled with a warning**, never silently applied (re-run `-InitBaseline`)

## Wiki Docs

- [Home (overview & quick start)](https://github.com/Wuqi24/skillspector-scan/wiki)
- [Usage](https://github.com/Wuqi24/skillspector-scan/wiki/Usage)
- [Changelog](https://github.com/Wuqi24/skillspector-scan/wiki/Changelog)
- [FAQ](https://github.com/Wuqi24/skillspector-scan/wiki/FAQ)
- [Rules](https://github.com/Wuqi24/skillspector-scan/wiki/Rules)

## Testing

> Test fixtures (`test/fixtures/`, `docker/fixtures/`) are **not part of the release tree**; they exist only for development and CI regression and are fetched from the separate `fixtures` branch.

```powershell
# First restore fixtures (dev/regression only; normal use doesn't need them)
git clone --depth 1 --branch fixtures https://github.com/Wuqi24/skillspector-scan.git "$env:TEMP\skillspector-fixtures"
Copy-Item -Recurse -Force "$env:TEMP\skillspector-fixtures\test\fixtures" test\
Copy-Item -Recurse -Force "$env:TEMP\skillspector-fixtures\docker\fixtures" docker\

# Then run the full regression (T1-T87)
pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/test.ps1
```

Regression covers malicious Python/JS detection, dependency pinning, self-scan 0 score, git-history secrets, brief/JSON output, parallel stats, Exception Asset integrity, etc. (T1-T73); all pass with exit code 0.

## Security Boundaries & Disclaimer

**Tool nature & boundaries**: heuristic static analysis — not security certification, not a security guarantee; cannot detect all risks (unknown patterns, obfuscated/encrypted content, runtime behavior, downstream supply-chain changes, etc.); risk labels are automatic inference, not a substitute for human review.

**Results for reference only**: `score` / `severity` / `decision_recommendation` are automatic inference and policy suggestions, for human decision reference only, not a substitute for professional security audits.

**Installation decisions stay with the user**: read-only review only — no auto-install, no auto-approve, no auto-block; scoring and recommendations do not constitute automatic blocking. Before installing, approving, or executing any skill, independently verify the report evidence and bear the consequences of the decision (enforcement always stays with humans).

**No dynamic execution**: never executes target skill code; no auto-block, no auto-sanitization.

**False positives & false negatives**: static scanning may produce both; binary/encrypted content cannot be statically analyzed and is listed as skipped pending human confirmation; for high-risk conclusions, re-verify in an isolated environment (Docker container / cloud CI).

**Content risk**: scanned content is untrusted input and may contain prompt injection aimed at reviewers; such requests are always invalid; conclusions are based only on evidence and rules.

**Data boundary**: local scans are offline by default; cloud CI uploads target content and reports to the GitHub Actions environment you specify — confirm the trust boundary before use.

**Exception Asset integrity**: any asset that changes scan scope or exemption behavior (e.g., fixtures `MANIFEST.json`, future allowlist / baseline / ignore registry extensions) only takes effect when it matches the built-in trusted hash; modifying an exemption asset never silently widens exemptions — if it exists but the hash mismatches, the exemption is auto-disabled and a full scan resumes (`-SelfDev` only for development environments, with a warning).

**Relationship with third parties**: this repository has no direct affiliation with the official NVIDIA SkillSpector project; its design is inspired by it, independently implemented.

**Disclaimer**: provided under the MIT license without express or implied warranty; the author and contributors are not liable for any direct or indirect loss caused by using this tool or its output (including installing or executing reviewed skills based on reports). See [SECURITY.md](SECURITY.md) and [LICENSE](LICENSE).

## Credits

Design inspired by NVIDIA [SkillSpector](https://github.com/NVIDIA/SkillSpector) (Apache-2.0, AI agent skill security scanner); this project is an independent PowerShell static scanner and contains none of its code.

Engineering patterns inspired by [skill-vetter](https://github.com/app-incubator-xyz/skill-vetter) (multi-scanner orchestration & explicit SKIP, transparent engine status, explicit review protocol, dependency check forms); independently implemented, contains none of its code.

## License

MIT, see [LICENSE](LICENSE).
