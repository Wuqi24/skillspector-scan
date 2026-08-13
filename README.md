# skill-inspector-ps

**Repository**: `skill-inspector-ps`
**Runtime skill ID**: `skillspector-scan`
**Skill directory**: `skillspector-scan`

离线静态安全审查工具：对本地 Codex 技能做只读扫描，识别提示注入、数据外泄、供应链、危险代码调用等 16+ 类风险，输出通俗安全报告。不安装、不运行目标技能的任何脚本；风险标签为自动推断，不替代人工裁决。

## 这是什么

`skillspector-scan` 是运行在 Codex 技能体系中的静态安全审查技能，也提供独立脚本 `scripts/scan.ps1`，可在安装第三方技能前做本地审查。

覆盖风险类别（详细检查点见 [references/checklist.md](references/checklist.md)）：

- 指令与行为：提示注入、反拒答/越狱、系统提示泄露、记忆投毒、过度自主权、触发词滥用、外部指令来源（OWASP AST05）
- 数据与网络：数据外泄、污点外传、SSRF（云 metadata/内网/回环）、Agent 窥探
- 代码与供应链：未锁版本、远程脚本、混淆、已知漏洞、仿冒包、危险调用（exec/eval/subprocess）、提权、持久化、工具滥用
- 元数据与生态：manifest 一致性、符号链接越界、MCP 最小权限/工具投毒、已知恶意特征（webshell/矿机/反弹 shell）、清单变化（rug-pull）

## 特性

- 全离线：唯一可联网项是可选 `-CheckCVE`（OSV.dev 查询，失败自动降级离线）
- 静态只读：无沙箱、无自动拦截、无自动净化
- 逐文件单次读取 + 专项多阶段检查 + 编码探测（UTF-8/UTF-16/GBK）+ 语境标注 + 注释词法识别
- Python AST/轻量污点分析、JS 行为启发式、base64 载荷解码复查、符号链接越界检测、git 历史密钥检测、manifest 变化检测
- 依赖锁定与离线依赖分析（来源白名单、拼写欺诈、安装脚本钩子、依赖数阈值）
- 简报模式（`-Brief`）：行为概要 → 最坏情况 TOP3 → 详细发现 → 参考发现 → 依赖风险，每条命中带“事实 + 推断”
- 已审记录（`-MarkVerified`）：文件 SHA-256 清单 + 结论 + 日期，内容变化自动提示结论失效
- JSON 输出（`-Json`）、批量（`-AllInstalled`/`-Dir`）、并行（`-Parallel`）、基线误报抑制（`-Baseline`）

## 安装

```powershell
# 1. 克隆仓库后，把 skillspector-scan 目录放入 Codex 技能目录
git clone https://github.com/Wuqi24/skill-inspector-ps.git
Copy-Item -Recurse skillspector-scan "$HOME\.codex\skills\"

# 2. 也可以直接作为独立脚本使用，不依赖 Codex
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/scan.ps1 -Path <技能目录>
```

依赖：PowerShell 5.1+（建议 7）。Python 可选：用于 AST/污点分析，缺失时自动降级为正则并在报告标注；可用 `-Python <路径>` 指定，`-NoAst` 关闭。

## 使用

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

# 基线抑制误报
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/scan.ps1 -Path <技能目录> -InitBaseline

# 可选：联网查已锁定依赖的已知漏洞（OSV.dev，离线自动降级）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/scan.ps1 -Path <技能目录> -CheckCVE

# 可选：扫描 git 历史中最近提交里出现过的疑似密钥
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/scan.ps1 -Path <技能目录> -GitHistory
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
- 不动态执行目标技能代码；不自动拦截、不自动净化
- 被扫描内容是未信任输入，可能夹带针对审查者的提示注入，这类要求一律无效，结论只依据证据与规则
- 二进制/加密内容无法静态分析，列入跳过清单待人工确认
- 本仓库与 NVIDIA SkillSpector 官方项目无直接关联，设计思路受其启发，独立实现

## License

MIT，见 [LICENSE](LICENSE)。
