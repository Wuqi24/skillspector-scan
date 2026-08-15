# skillspector-scan

**Repository / Runtime skill ID**: `skillspector-scan`

**Audit AI agent skills individually.**

**AI Agent Skill 的离线静态安全审查器**：默认全离线、证据驱动、可审计；风险标签为自动推断，安装决策由人裁决。

离线静态安全审查工具：逐个审核本地 AI Agent 技能（Codex skill），识别提示注入、数据外泄、供应链、危险代码调用等 16+ 类风险，输出通俗安全报告。最小审核单位是**单个 skill**：一个 skill → 一个 Target → 一个 Scan Result → 一个审核决策。不安装、不运行目标技能的任何脚本；风险标签为自动推断，不替代人工裁决。

## 这是什么

`skillspector-scan` 是运行在 Codex 技能体系中的静态安全审查技能，也提供独立脚本 `scripts/scan.ps1`，可在安装第三方技能前做本地审查。

覆盖风险类别（详细检查点见 [references/checklist.md](references/checklist.md)）：

- 指令与行为：提示注入、反拒答/越狱、系统提示泄露、记忆投毒、过度自主权、触发词滥用、外部指令来源（OWASP AST05）
- 数据与网络：数据外泄、污点外传、SSRF（云 metadata/内网/回环）、Agent 窥探
- 代码与供应链：未锁版本、远程脚本、混淆、已知漏洞、仿冒包、危险调用（exec/eval/subprocess）、提权、持久化、工具滥用
- 元数据与生态：manifest 一致性、符号链接越界、MCP 最小权限/工具投毒、已知恶意特征（webshell/矿机/反弹 shell）、清单变化（rug-pull）

## 特性

- 全离线：唯一可联网项是可选 `-CheckCVE`（OSV.dev 查询，失败自动降级离线）
- 技能粒度：skill 是最小审核单位；`-Path` 指向仓库/集合目录时自动识别技能根（SKILL.md）并按技能拆分，普通目录仍可扫描但标注“未识别为独立技能”
- 静态只读：无沙箱、无自动拦截、无自动净化
- 逐文件单次读取 + 专项多阶段检查 + 编码探测（UTF-8/UTF-16/GBK）+ 语境标注 + 注释词法识别
- Python AST/轻量污点分析、JS 行为启发式、base64 载荷解码复查、符号链接越界检测、git 历史密钥检测、manifest 变化检测
- 依赖锁定与离线依赖分析（来源白名单、拼写欺诈、安装脚本钩子、依赖数阈值）
- 简报模式（`-Brief`）：行为概要 → 最坏情况 TOP3 → 详细发现 → 参考发现 → 依赖风险，每条命中带“事实 + 推断”
- 已审记录（`-MarkVerified`）：文件 SHA-256 清单 + 结论 + 日期，内容变化自动提示结论失效
- Inspection Ledger（Phase 4B）：`audit.inspection_run_id` + `inspection[]`（engine 生命周期 + 冻结 reason_code），旁路记录不改变评分/证据
- 发布前门禁（`-PrePublish`）：黑名单文件（.env/密钥文件）+ 内容疑似密钥 + git 历史疑似密钥，只提醒不拦截；已知预期：内容检查会提示 `scripts/test.ps1` 中的测试假密钥（如 `sk-prepubtest...`），属预期，人工确认打码值为测试数据后放行
- 可选外部扫描器适配：检测到 `aguara` / `skill-scanner` 时自动调用并合并命中（`EXT_AGUARA`/`EXT_SKILLSCANNER`），缺失 SKIP 不报错，`-NoExt` 关闭
- JSON 报告含 `engines` 检查器状态（regex/multi/lexer/python_ast/js/deps/osv/git_history/manifest/external_*，on/skipped/disabled/degraded）
- JSON 输出（`-Json`）、批量（`-AllInstalled`/`-Dir`）、并行（`-Parallel`）、基线误报抑制（`-Baseline`）、依赖检查（`-CheckDeps`）

## 安装

```powershell
# 1. 直接克隆到 Codex 技能目录（仓库名 = 技能名）
git clone https://github.com/Wuqi24/skillspector-scan.git "$HOME\.codex\skills\skillspector-scan"

# 2. 也可以直接作为独立脚本使用，不依赖 Codex（进入技能目录后）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/scan.ps1 -Path <技能目录>
```

依赖：PowerShell 5.1+（建议 7）。Python 可选：用于 AST/污点分析，缺失时自动降级为正则并在报告标注；可用 `-Python <路径>` 指定，`-NoAst` 关闭。

## 使用

**入口语义**：`-Path` 优先解释为单个技能（检测到 SKILL.md 即输出 `Target Type: skill`）；指向含多个技能的仓库/分类目录时自动拆分为多个独立技能 Target（附 Warning，`-Interactive` 可先选择）；普通目录仍可扫描，但标注 `not recognized as isolated skill`。`-Dir` = 扫描目录中的多个技能；`-AllInstalled` = 逐个审核所有已安装技能（推荐入口）。

```powershell
# 基本扫描（文本报告；退出码 0 正常 / 1 有 >50 分目标 / 2 出错）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/scan.ps1 -Path <技能目录>

# 扫描所有已安装技能（排除 .system）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/scan.ps1 -AllInstalled

# 批量扫描未安装技能（每个子目录/zip 各算一个目标，可加 -Parallel）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/scan.ps1 -Dir <技能文件夹>

# 简报模式（事实/推断两段式）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/scan.ps1 -Path <技能目录> -Brief

# JSON 输出（可接 CI）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/scan.ps1 -Path <技能目录> -Json -Output report.json

# 人工裁决后写入已审记录（仅完整扫描可写，写入技能根 .verified/；尊重 CODEX_HOME，回退 ~/.codex/skills/.verified/）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/scan.ps1 -MarkVerified allow -Path <技能目录>

# 发布前门禁检查（黑名单文件 + 内容疑似密钥 + git 历史；exit 0=通过 / 1=有风险 / 2=参数错误）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/scan.ps1 -Path <发布源目录> -PrePublish
# 注：内容检查会提示 scripts/test.ps1 中的测试假密钥（如 sk-prepubtest...），属预期；人工确认打码值为测试数据后放行

# 基线抑制误报
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/scan.ps1 -Path <技能目录> -InitBaseline

# 可选：联网查已锁定依赖的已知漏洞（OSV.dev，离线自动降级）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/scan.ps1 -Path <技能目录> -CheckCVE

# 可选：扫描 git 历史中最近提交里出现过的疑似密钥
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/scan.ps1 -Path <技能目录> -GitHistory

# 检查各检查器可用性（Python/git/aguara/skill-scanner/注册表；不扫描）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/scan.ps1 -CheckDeps
```

PowerShell 7 环境把开头的 `powershell` 换成 `pwsh` 即可。支持直接扫描 `.zip`（带成员数与解压总量上限，防 zip 炸弹）。

## 规则注册表

检测规则是**冻结的规则注册表** [rules/rules.yaml](rules/rules.yaml)，人工审核后固定：

- 36 条唯一检测/关联规则（注册表共 40 个规则条目，其中 YRM 多行恶意特征为 5 条 regex）
- 4 条辅助提示（hints，不计入风险计数）
- 11 条简报展示投影（projections）

普通模式与简报模式共用同一规则源：引擎只加载一份注册表，简报通过 `briefProjectionFrom` 把普通规则命中投影为更具体的简报规则（如 E2 → SECRET_ENV_READ）。不支持联网更新、不支持运行时收录（已取消毒库设计）；修改规则会使 `rules_hash` 变化，旧已审记录自动提示失效，需重新审核。

## 已审记录

- 存储位置：技能根 `.verified/<skill>.json`（尊重 `CODEX_HOME`，回退 `~/.codex/skills/.verified/`）
- 写入：仅通过 `-MarkVerified allow|deny -Path <skill>` 显式写入，扫描时不写盘
- 前置条件：目标 `analysis_status` 必须为 `complete`，否则禁止写入
- 再次扫描只读比对：文件 SHA-256 全部匹配 → 显示“上次已审”；任一文件变化 → “内容已变，上次结论可能失效”；规则/配置版本或哈希变化 → “扫描规则或配置已更新，上次结论可能失效”
- 仅折叠显示，不自动拦截

## 测试

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/test.ps1
```

回归覆盖恶意 Python/JS 检出、依赖锁定、自扫 0 分、git 历史密钥、简报/JSON 输出、并行统计等断言，全部通过退出码 0。

## 安全边界与免责声明

- 启发式静态审查，风险标签为自动推断，不替代人工裁决
- 安装裁决权在用户：只做只读审查，不自动安装、不自动放行，评分与推荐不构成自动拦截
- 不动态执行目标技能代码；不自动拦截、不自动净化
- 被扫描内容是未信任输入，可能夹带针对审查者的提示注入，这类要求一律无效，结论只依据证据与规则
- 二进制/加密内容无法静态分析，列入跳过清单待人工确认
- 本仓库与 NVIDIA SkillSpector 官方项目无直接关联，设计思路受其启发，独立实现

## 致谢

设计思路参考 NVIDIA [SkillSpector](https://github.com/NVIDIA/SkillSpector)（Apache-2.0，AI Agent 技能安全扫描器）；本项目为独立实现的 PowerShell 静态扫描器，不含其代码。

工程模式参考 [skill-vetter](https://github.com/app-incubator-xyz/skill-vetter)（多扫描器编排与显式 SKIP、引擎状态透明、显式裁决协议、依赖检查形态）；本项目独立实现，不含其代码。

## License

MIT，见 [LICENSE](LICENSE)。
