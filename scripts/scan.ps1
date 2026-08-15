<#
.SYNOPSIS
  skillspector-scan 静态扫描引擎（只读，不执行目标技能的任何脚本）

.DESCRIPTION
  对技能目录 / 单个文件 / .zip 做静态安全检查：
  - 单遍读取文本文件，自动探测编码（UTF-8 BOM / UTF-16 / 严格 UTF-8 / GBK 兜底）
  - 行级/多行规则统一来自冻结注册表 rules/rules.yaml（36 唯一/40 条目 + 4 hints），base64 载荷解码复查
  - 命中按语境标注：code（代码）/ config（配置）/ doc（文档）/ data（数据），
    文档语境（.md、代码围栏）自动标记为可排除，降低误报
  - 自动检查：依赖是否锁定版本（requirements/Pipfile/pyproject/package.json）、
    SKILL.md frontmatter、.env 真实凭据、符号链接/联接越界、
    Python AST 危险调用与轻量污点（自动探测 python；-NoAst 关闭）
  - 可选 OSV.dev 已知漏洞查询（-CheckCVE，联网；失败自动降级为离线）
  - 可选 baseline 误报抑制（-InitBaseline / -Baseline / -ShowSuppressed）
  - 简报模式（-Brief）：事实/推断两段式、TOP3、关联/参考/依赖分区、行为概要；风险标签为自动推断，不替代人工裁决
  - 已审记录（-MarkVerified allow|deny）：写入技能根目录下 .verified/（尊重 CODEX_HOME，回退 ~/.codex/skills/.verified/），扫描时只读比对文件 SHA-256 清单
  - 输出文本或 JSON（-Json），可写文件（-Output）
  - 退出码：0 正常 / 1 存在 score>50 的目标 / 2 出错

.PARAMETER Path
  技能目录、单个文件或 .zip
.PARAMETER AllInstalled
  扫描全部已安装技能（自动定位 skills 根目录，不再硬编码路径）
.PARAMETER Dir
  批量扫描未安装技能：指定一个文件夹，扫描其中每个子目录（跳过隐藏目录）与每个 .zip，输出批量汇总
.PARAMETER Json
  输出 JSON 报告
.PARAMETER Output
  把报告写入指定文件（UTF-8 无 BOM）
.PARAMETER Baseline
  基线文件（.skillspector-baseline.yaml），抑制指纹匹配的发现
.PARAMETER InitBaseline
  把当前非文档发现写入基线文件（默认写到目标目录内）
.PARAMETER ShowSuppressed
  显示被基线抑制的发现
.PARAMETER CheckCVE
  联网查询 OSV.dev（仅已锁定版本依赖；网络不可用时自动跳过并记录）
.PARAMETER MaxFileBytes
  单文件分析上限，默认 1MB
.PARAMETER Python
  指定 python 可执行文件；默认自动探测
.PARAMETER NoAst
  跳过 Python AST 分析
.PARAMETER Parallel
  批量模式并行扫描（每个目标一个后台进程，最多 4 个并发）
.PARAMETER Worker
  内部参数：作为并行工作进程只扫单个目标并输出 JSON
.PARAMETER GitHistory
  扫描 git 历史（最近 N 次提交的完整补丁）中的疑似密钥
.PARAMETER GitDepth
  git 历史扫描深度（提交数），默认 20
.PARAMETER Full
  展开全部命中明细（默认只输出风险概览与关键发现）
.PARAMETER Brief
  简报模式：事实/推断两段式输出（行为概要 → TOP3 → 详细 → 参考 → 依赖）
.PARAMETER Score
  显示自动评分摘要（仅 -Brief 模式有效；自动推断指标，不代表放行/拒绝）
.PARAMETER Interactive
  多目标简报模式下进入序号交互（单目标时忽略；与 -Parallel 同用忽略）
.PARAMETER SelfDev
  开发模式：自扫豁免跳过核心文件哈希校验（保留文件集白名单）
.PARAMETER RebakeSelfHashes
  重算核心文件 SHA-256 并刷新 scan.ps1 内自扫哈希常量块，然后退出
.PARAMETER RegistryStats
  输出规则注册表统计（条目数/唯一 id/regex 编译校验）并退出
.PARAMETER CheckDeps
  输出各检查器可用性（Python/git/aguara/skill-scanner/注册表）并退出，不扫描
.PARAMETER NoExt
  关闭可选外部扫描器适配层（aguara / skill-scanner；默认自动探测，缺失则 SKIP）
.PARAMETER MarkVerified
  显式写入已审记录：allow|deny，必须与 -Path 配对；禁止与简报/导出参数同用
.PARAMETER PrePublish
  发布前门禁检查：黑名单文件（.env/密钥文件）+ 内容疑似密钥 + git 历史疑似密钥；只提醒不拦截（exit 0=通过 / 1=有风险 / 2=参数或环境错误）
#>
[CmdletBinding()]
param(
  [string]$Path,
  [switch]$AllInstalled,
  [string]$Dir,
  [switch]$Json,
  [string]$Output,
  [string]$Baseline,
  [switch]$InitBaseline,
  [switch]$ShowSuppressed,
  [switch]$CheckCVE,
  [int]$MaxFileBytes = 1048576,
  [string]$Python,
  [switch]$NoAst,
  [switch]$Parallel,
  [switch]$Worker,
  [switch]$GitHistory,
  [int]$GitDepth = 20,
  [switch]$Full,
  [switch]$Brief,
  [switch]$Score,
  [switch]$Interactive,
  [switch]$SelfDev,
  [switch]$RebakeSelfHashes,
  [switch]$RegistryStats,
  [switch]$CheckDeps,
  [switch]$NoExt,
  [ValidateSet('allow', 'deny')][string]$MarkVerified,
  [switch]$PrePublish
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
$OutputEncoding = [System.Text.Encoding]::UTF8

$skillName = 'skillspector-scan'
$scannerVersion = '2.4.0'
$policyVersion = '1.0'
$script:ReasonCodes = @(
  'binary_asset', 'binary_content', 'oversized', 'permission_denied', 'unsupported_encoding',
  'external_missing', 'not_applicable', 'no_files', 'parse_error', 'dependency_unresolved',
  'disabled_by_config', 'unknown'
)
$instructionIds = @('AR', 'P1', 'SPL', 'MP', 'EA', 'TR', 'AST05')
# 自扫豁免哨兵：随脚本分发；修改脚本无需更新此常量，改名目录/复制公开文件无法伪造完整扫描器
$SelfMarker = 'skillspector-scan@self-7f3a9c21e5b84d06'
# 自扫豁免核心文件集（文件集白名单：目录内出现集外文件 → 不豁免，堵“整包复制+新增文件”绕过）
$selfCoreFiles = @(
  '.dockerignore', '.github/workflows/skill-scan.yml', 'SKILL.md', 'README.md', 'LICENSE',
  'test/fixtures/MANIFEST.json', 'contracts/reason-codes.md',
  'agents/openai.yaml', 'data/known_packages.json', 'docker/Dockerfile', 'docker/README.md',
  'docker/fixtures/evil-test/SKILL.md', 'docker/fixtures/evil-test/scripts/evil.py',
  'references/checklist.md', 'references/scan-patterns.md', 'rules/rules.yaml',
  'scripts/scan.ps1', 'scripts/ast_check.py', 'scripts/lexer.py', 'scripts/test.ps1'
)
# __SELF_HASHES_BEGIN__
# 核心文件 SHA-256（除 scan.ps1 自身，其哈希无法自嵌）。编辑任一核心文件后运行 -RebakeSelfHashes 刷新。
$SelfHashes = @{
  '.dockerignore' = '6A109BD62F1C1078D8F206A37B7E76A93765CC59C2457CADF841E46C3A7DB5BB'
  '.github/workflows/skill-scan.yml' = 'ECBA2A6603626DC6C9BC56B6E2D323838E11F276E2BDBA033AC6EAE861A5DC26'
  'SKILL.md' = '3D2D30CC6B10D41A0B48D5BFFFE358CC1F88A2858BF447979A5A6740533173A8'
  'README.md' = 'E2214066693189ED0D0102DCD4BCF30ECCC8E936D3D39E6D91580B9BDD099096'
  'LICENSE' = '9BA0B05F574B91E98B15A912BE0DF6466544AE4E4F82108B58B4814B7F9B2E68'
  'test/fixtures/MANIFEST.json' = '9C19ADA10CD7B243498B15E9D14F5EDFA3A4D6ACD5B777F920A0961CBE1EC658'
  'contracts/reason-codes.md' = '0859DB5C0F0C379825ED62D9F134CDBE4FC9906CD5D0CD395996D058E5F1964C'
  'agents/openai.yaml' = 'E6C82E9AA477A2A8107FFB081EF5AB9FA61E67065C54F1632CE15842E6E618BC'
  'data/known_packages.json' = '703A9F18DA2F80AC42C4D4D2798BEE59DB2A83EBF45169E65E2569969846A099'
  'docker/Dockerfile' = '6A46DAB6D5E26B8512D10219C472C16F606DDBFB0DCB30DB0832FD811933F99F'
  'docker/README.md' = '7A344A6661AF66F698E3355DCABCBC78B8ECAF99791AC332176F263EB37F3590'
  'docker/fixtures/evil-test/SKILL.md' = 'A51983B210FBEB5FE91DD2ADA18236E1755ADD2AB26787AB5D4E6F9EC87B29D9'
  'docker/fixtures/evil-test/scripts/evil.py' = 'F0A93241522671E89CF848F6489D4864143636EF2B90E52F849CA039B132981E'
  'references/checklist.md' = '5FA0A3BE7A4B2FFD6C19686001BC2597C5B35ABC25DBFBAEC803EC2F751BF1C4'
  'references/scan-patterns.md' = '100B4CD762F2C1EA4BB7133132E45F706F9CAE81DEB70CB64795145E7764CF7D'
  'rules/rules.yaml' = 'F1CB18C73370BA7BD4EDA7E1F13A72B295704FB3F44C75610C736A501C3075F8'
  'scripts/ast_check.py' = 'E1B6E8B78423C05B61790E7AC486DEA3694644A226F962D744F4181828125A5F'
  'scripts/lexer.py' = '09D9FDD1A0DAE38FA52370D3DE22AEC52DAA250823D97B14E9AA6904DCE877E2'
  'scripts/test.ps1' = '493FC2C6C36645BF2E7A083444CCF1020E00732E75AFE19ADBA0B8378420527C'
}
# __SELF_HASHES_END__
$astScript = Join-Path $PSScriptRoot 'ast_check.py'
$lexerScript = Join-Path $PSScriptRoot 'lexer.py'
$scriptPath = $MyInvocation.MyCommand.Path
if (-not $scriptPath) { $scriptPath = Join-Path $PSScriptRoot 'scan.ps1' }
$sevPoints = @{ CRITICAL = 50; HIGH = 25; MEDIUM = 10; MED = 10; LOW = 5 }

# 已知无害静态资产（binary_asset：跳过但不影响覆盖完整性，不计 partial）
$assetExt = @(
  '.png','.jpg','.jpeg','.gif','.webp','.ico',
  '.ogg','.mp3','.mp4','.wav','.avi','.mov',
  '.ttf','.woff','.woff2','.otf','.eot'
)
# 无法确认无害的二进制（binary：影响覆盖完整性 → partial）
$binaryExt = @(
  '.jar','.zip','.7z','.rar','.exe','.dll','.bin','.dat','.iso','.o','.so','.dylib',
  '.pdf','.doc','.docx','.xls','.xlsx','.ppt','.pptx',
  '.pyc','.pyo','.whl','.deb','.rpm','.apk'
)
$skipExt = @($assetExt) + @($binaryExt)
# 已知可文本扫描的扩展名（内容嗅探只对不在此列表的文件执行）
$knownTextExt = @(
  '.md','.markdown','.rst','.yaml','.yml','.json','.toml','.xml','.ini','.cfg','.conf',
  '.editorconfig','.gitignore','.gitattributes','.dockerignore','.svg','.lock','.html','.htm',
  '.py','.pyw','.js','.mjs','.cjs','.ts','.tsx','.jsx','.sh','.bash','.zsh','.ps1','.psm1','.psd1',
  '.bat','.cmd','.rb','.pl','.lua','.go','.rs','.c','.cpp','.h','.java','.kt','.php','.swift','.sql'
)

# 引擎内置 ID 的通俗说明与 OWASP 映射（AST/专项检查器产出的引擎 ID + 注册表中缺 owasp 字段的规则兜底）。
# 注册表加载成功后按“仅补缺失项”合并进 $descMap/$owaspMap；本表不参与规则匹配，不是第二规则源。
$engineMap = @{
  DC1  = @{ desc = '危险代码调用（exec）'; owasp = 'AST01' }
  DC2  = @{ desc = '危险代码调用（eval）'; owasp = 'AST01' }
  DC3  = @{ desc = '动态导入（__import__）'; owasp = 'AST01' }
  DC4  = @{ desc = '执行外部进程'; owasp = 'AST01' }
  DC6  = @{ desc = '危险代码调用（compile）'; owasp = 'AST01' }
  DC8  = @{ desc = '非字面量动态执行'; owasp = 'AST01' }
  TT3  = @{ desc = '密钥/凭据流向网络'; owasp = 'AST06' }
  TT5  = @{ desc = '外部输入流入代码执行'; owasp = 'AST06' }
  SC1  = @{ desc = '依赖未锁定版本'; owasp = 'AST02' }
  SC4  = @{ desc = '依赖存在已知漏洞'; owasp = 'AST02' }
  DEP_SOURCE      = @{ desc = '依赖源不在白名单'; owasp = 'AST02' }
  DEP_TYPOSQUAT   = @{ desc = '疑似拼写相似包'; owasp = 'AST02' }
  DEP_HOOK        = @{ desc = '安装脚本钩子'; owasp = 'AST02' }
  DEP_COUNT       = @{ desc = '直接依赖数超阈值'; owasp = 'AST02' }
  DEP_UNDECLARED  = @{ desc = '未声明依赖'; owasp = 'AST02' }
  MD      = @{ desc = '元数据/命名问题'; owasp = 'AST04' }
  SYMLINK = @{ desc = '链接指向技能目录外'; owasp = 'AST06' }
  RP      = @{ desc = '安装后清单被改动（rug-pull）'; owasp = 'AST07' }
  YRM  = @{ desc = '多行恶意特征'; owasp = 'AST01' }
  DC   = @{ desc = '危险代码调用（执行命令/动态执行）'; owasp = 'AST01' }
  DC7  = @{ desc = '动态属性访问'; owasp = 'AST01' }
  SC2  = @{ desc = '远程下载并执行'; owasp = 'AST02' }
  SC3  = @{ desc = '混淆/编码后执行'; owasp = 'AST01' }
  RA   = @{ desc = '持久化/开机自启'; owasp = 'AST03' }
  PE   = @{ desc = '提权或绕过限制'; owasp = 'AST03' }
  TM   = @{ desc = '工具参数滥用'; owasp = 'AST03' }
  DEL  = @{ desc = '删除类危险操作'; owasp = 'AST01' }
  CRED = @{ desc = '疑似密钥/凭据'; owasp = 'AST01' }
  YR1  = @{ desc = '恶意特征（反弹shell/木马）'; owasp = 'AST01' }
  YR2  = @{ desc = '恶意特征（webshell）'; owasp = 'AST01' }
  YR3  = @{ desc = '恶意特征（挖矿）'; owasp = 'AST01' }
  YR4  = @{ desc = '恶意特征（攻击工具）'; owasp = 'AST01' }
  E2   = @{ desc = '读取环境变量/密钥'; owasp = 'AST06' }
  E3   = @{ desc = '扫描敏感文件/目录'; owasp = 'AST03' }
  E5   = @{ desc = '上传到云存储'; owasp = 'AST06' }
  SSRF = @{ desc = '访问内网或云元数据地址'; owasp = 'AST06' }
  AS   = @{ desc = '窥探其他代理配置'; owasp = 'AST03' }
  OBS  = @{ desc = '混淆内容（base64等）'; owasp = 'AST04' }
  ZW   = @{ desc = '隐藏不可见字符'; owasp = 'AST04' }
  PUBLIC_IP_CALL         = @{ desc = '向公网 IP 发起网络调用'; owasp = 'AST06' }
  INSECURE_HTTP_CALL     = @{ desc = '向非 HTTPS 域名发起网络调用'; owasp = 'AST06' }
  BROWSER_SESSION_ACCESS = @{ desc = '访问浏览器 Cookie/会话'; owasp = 'AST06' }
  INSTALL_HOOK           = @{ desc = '安装脚本钩子'; owasp = 'AST02' }
  UNDECLARED_INSTALL     = @{ desc = '未声明安装软件包'; owasp = 'AST02' }
  LOOPBACK_ACCESS   = @{ desc = '回环地址访问'; owasp = 'AST06' }
  AGENT_MEMORY_FILE = @{ desc = '访问 AI 身份/记忆文件'; owasp = 'AST03' }
  INTERNAL_NET_CALL = @{ desc = '向内网地址发起网络调用'; owasp = 'AST06' }
  OBFUSCATION       = @{ desc = '混淆代码（极长单行）'; owasp = 'AST04' }
  EXT_AGUARA        = @{ desc = '外部扫描器 aguara 命中（提示注入/混淆/可疑 LLM 调用）'; owasp = 'AST01' }
  EXT_SKILLSCANNER  = @{ desc = '外部扫描器 skill-scanner 命中（已知恶意模式/CVE）'; owasp = 'AST02' }
}

# ---------- 规则注册表（冻结版，非毒库） ----------
$registry = @{ rules = @(); hints = @(); config = @{}; rules_version = '2.0.0'; schema_version = '1.0.0' }
$registryLoaded = $false

function ConvertTo-CanonicalJson {
  # 键排序、数组保序的规范化 JSON 序列化（用于 finding_id / fingerprint / 版本哈希）
  param($InputObject)
  if ($InputObject -is [System.Collections.IDictionary]) {
    $pairs = @()
    foreach ($k in ($InputObject.Keys | Sort-Object)) {
      $escKey = [string]$k
      $escKey = $escKey.Replace('\', '\\').Replace('"', '\"')
      $pairs += ('"' + $escKey + '":' + (ConvertTo-CanonicalJson $InputObject[$k]))
    }
    return '{' + ($pairs -join ',') + '}'
  }
  if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
    $h = @{}
    foreach ($prop in $InputObject.PSObject.Properties) { $h[$prop.Name] = $prop.Value }
    return ConvertTo-CanonicalJson $h
  }
  if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
    $items = @()
    foreach ($e in $InputObject) { $items += (ConvertTo-CanonicalJson $e) }
    return '[' + ($items -join ',') + ']'
  }
  if ($null -eq $InputObject) { return 'null' }
  if ($InputObject -is [bool]) { return $InputObject.ToString().ToLower() }
  if ($InputObject -is [int] -or $InputObject -is [long] -or $InputObject -is [double]) { return $InputObject.ToString() }
  $s = [string]$InputObject
  $s = $s.Replace('\', '\\').Replace('"', '\"')
  return '"' + $s + '"'
}

function Get-Sha256Hex {
  param([string]$Text)
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $h = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))
    return ([System.BitConverter]::ToString($h)).Replace('-', '').ToLower()
  } finally { $sha.Dispose() }
}

function Get-HashOfFile {
  param([string]$Path)
  return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash
}

function ConvertFrom-SimpleYaml {
  # 解析 rules/rules.yaml 的固定结构（key: value / 列表 - value / 对象列表 - key: value）
  param([string]$Path)
  $root = @{}
  $cur = $root
  $curIndent = -1
  $stack = New-Object System.Collections.Stack
  $pendingList = $null
  $pendingItem = $null
  $pendingItemIndent = -1
  $pendingContainer = $null   # @{ parent=..; key=..; indent=.. }
  function ConvertFrom-SimpleYaml-Unquote {
    param([string]$v)
    $v = $v.Trim()
    if ($v.Length -ge 2 -and (($v.StartsWith("'") -and $v.EndsWith("'")) -or ($v.StartsWith('"') -and $v.EndsWith('"')))) {
      return $v.Substring(1, $v.Length - 2)
    }
    return $v
  }
  foreach ($raw in @(Get-Content -Encoding UTF8 -LiteralPath $Path)) {
    if ($raw -match '^\s*(#.*)?$') { continue }
    $indent = if ($raw -match '^(\s*)\S') { $matches[1].Length } else { 0 }
    $line = $raw.Trim()
    if ($line -match '^-\s+(.+)$') {
      $itemText = $matches[1]
      if ($pendingContainer -and $indent -gt $pendingContainer.indent) {
        $list = New-Object System.Collections.ArrayList
        $pendingContainer.parent[$pendingContainer.key] = $list
        $pendingList = $list
        $pendingContainer = $null
      }
      if ($itemText -match '^([A-Za-z0-9_]+):\s*(.*)$') {
        $item = @{}
        if ($null -eq $pendingList) { throw '列表项不在列表容器中: ' + $itemText }
        [void]$pendingList.Add($item)
        $pendingItem = $item
        $pendingItemIndent = $indent
        if ($matches[2] -ne '') { $item[$matches[1]] = ConvertFrom-SimpleYaml-Unquote $matches[2] }
      } else {
        if ($null -eq $pendingList) { throw '列表项不在列表容器中: ' + $itemText }
        [void]$pendingList.Add((ConvertFrom-SimpleYaml-Unquote $itemText))
        $pendingItem = $null
      }
      continue
    }
    if ($line -match '^([A-Za-z0-9_]+):\s*(.*)$') {
      $key = $matches[1]
      $val = $matches[2]
      $target = $null
      if ($pendingItem -and $indent -gt $pendingItemIndent) { $target = $pendingItem }
      else {
        while ($stack.Count -gt 0 -and $indent -le $curIndent) {
          $top = $stack.Pop()
          $cur = $top.obj
          $curIndent = $top.indent
        }
        $target = $cur
        $pendingItem = $null
      }
      if ($val -eq '') {
        $pendingContainer = @{ parent = $target; key = $key; indent = $indent }
      } else {
        $pendingContainer = $null
        $target[$key] = ConvertFrom-SimpleYaml-Unquote $val
        if (-not $target.ContainsKey($key) -or $target[$key] -is [string]) { }
      }
      continue
    }
    throw '无法解析的 YAML 行: ' + $raw
  }
  return $root
}

function Get-RegistryRules {
  # 加载规则注册表（rules/rules.yaml，唯一规则源）；由注册表生成统一规则集（普通+简报共用）
  $path = Join-Path (Split-Path $PSScriptRoot -Parent) 'rules\rules.yaml'
  if (-not (Test-Path -LiteralPath $path)) { return $false }
  try {
    $o = ConvertFrom-SimpleYaml $path
    if (-not $o.rules -or @($o.rules).Count -lt 5) { throw '规则注册表缺少 rules 或过少' }
    $script:registry = @{
      rules = @($o.rules)
      hints = @($o.hints)
      projections = @($o.projections)
      config = $o.config
      rules_version = [string]$o.rules_version
      schema_version = [string]$o.schema_version
    }
    # severity 归一：注册表新四类 → 普通模式内部旧值（简报渲染时再投影回新四类）
    $sevMap = @{ critical = 'HIGH'; suspicious = 'MEDIUM'; info = 'LOW' }
    $lp = New-Object System.Collections.ArrayList
    $mp = New-Object System.Collections.ArrayList
    $hp = New-Object System.Collections.ArrayList
    $script:descMap = @{}
    $script:owaspMap = @{}
    $script:ruleCategory = @{}
    $script:rulePriority = @{}
    foreach ($r in @($o.rules)) {
      if (-not $r.regex) { continue }
      $isMulti = ("$($r.multi)" -eq 'true')
      $sev = if ($sevMap.ContainsKey([string]$r.severity)) { $sevMap[[string]$r.severity] } else { [string]$r.severity }
      $scoreVal = $true
      if ($null -ne $r.score) { $scoreVal = -not ("$($r.score)" -eq 'false') }
      $item = [pscustomobject]@{ id = $r.rule_id; sev = $sev; re = $r.regex; multi = $isMulti; score = $scoreVal }
      if ($isMulti) { [void]$mp.Add($item) } else { [void]$lp.Add($item) }
      if ($r.description) { $script:descMap[$r.rule_id] = [string]$r.description }
      if ($r.owasp) { $script:owaspMap[$r.rule_id] = [string]$r.owasp }
      if ($r.category) { $script:ruleCategory[$r.rule_id] = [string]$r.category }
      $script:rulePriority[$r.rule_id] = if ($null -ne $r.rule_priority) { [int]$r.rule_priority } else { 0 }
    }
    foreach ($h in @($o.hints)) {
      if (-not $h.regex) { continue }
      [void]$hp.Add([pscustomobject]@{ id = $h.rule_id; sev = [string]$h.severity; re = $h.regex; multi = $false; score = $false })
      if ($h.description) { $script:descMap[$h.rule_id] = [string]$h.description }
      if ($h.category) { $script:ruleCategory[$h.rule_id] = [string]$h.category }
      $script:rulePriority[$h.rule_id] = if ($null -ne $h.rule_priority) { [int]$h.rule_priority } else { 0 }
    }
    $script:linePatterns = @($lp)
    $script:multiPatterns = @($mp)
    $script:hintPatterns = @($hp)
    # 引擎内置兜底：注册表未覆盖的引擎 ID 与缺 owasp 字段的规则，补 desc/OWASP 映射（仅补缺失项）
    foreach ($k in @($engineMap.Keys)) {
      $em = $engineMap[$k]
      if (-not $script:descMap.ContainsKey($k) -and $em.desc) { $script:descMap[$k] = $em.desc }
      if (-not $script:owaspMap.ContainsKey($k) -and $em.owasp) { $script:owaspMap[$k] = $em.owasp }
    }
    # 简报展示投影：普通规则命中在简报模式下显示为更具体的简报规则
    $script:briefProjectionFrom = @{}
    foreach ($pj in @($o.projections)) {
      $pjObj = [pscustomobject]@{
        brief_id = [string]$pj.rule_id; severity = [string]$pj.severity
        priority = if ($null -ne $pj.priority) { [int]$pj.priority } else { 0 }
        category = [string]$pj.category; description = [string]$pj.description
      }
      $script:briefProjectionFrom[[string]$pj.from] = $pjObj
      if ($pj.rule_id -and -not $script:descMap.ContainsKey([string]$pj.rule_id)) { $script:descMap[[string]$pj.rule_id] = [string]$pj.description }
    }
    $script:registryLoaded = $true
    return $true
  } catch {
    Write-Output ('警告: 规则注册表解析失败: ' + $_.Exception.Message)
    return $false
  }
}

function Get-RegistryHashes {
  # 内容规范化哈希：rules.yaml / config / known_packages.json（键排序后 canonical JSON → SHA-256）
  $rulesPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'rules\rules.yaml'
  $kpPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'data\known_packages.json'
  $rulesHash = ''
  $configHash = ''
  $kpHash = ''
  $kpVersion = ''
  if (Test-Path -LiteralPath $rulesPath) {
    $o = ConvertFrom-SimpleYaml $rulesPath
    $rulesHash = Get-Sha256Hex (ConvertTo-CanonicalJson (@($o.rules) + @($o.hints)))
    $configHash = Get-Sha256Hex (ConvertTo-CanonicalJson $o.config)
  }
  if (Test-Path -LiteralPath $kpPath) {
    try {
      $kp = Get-Content -Raw -Encoding UTF8 -LiteralPath $kpPath | ConvertFrom-Json
      $kpHash = Get-Sha256Hex (ConvertTo-CanonicalJson $kp.packages)
      $kpVersion = [string]$kp.version
    } catch { $kpHash = '' }
  }
  return [pscustomobject]@{
    rules_hash = $rulesHash
    config_hash = $configHash
    known_packages_hash = $kpHash
    known_packages_version = $kpVersion
    schema_hash = Get-Sha256Hex $registry.schema_version
  }
}

function Write-SelfHashes {
  # 重算核心文件（除 scan.ps1 自身）的 SHA-256，重写 scan.ps1 标记块内的 $SelfHashes 常量
  $skillDir = Split-Path $PSScriptRoot -Parent
  $lines = New-Object System.Collections.ArrayList
  [void]$lines.Add('# __SELF_HASHES_BEGIN__')
  [void]$lines.Add('# 核心文件 SHA-256（除 scan.ps1 自身，其哈希无法自嵌）。编辑任一核心文件后运行 -RebakeSelfHashes 刷新。')
  [void]$lines.Add('$SelfHashes = @{')
  foreach ($rel in @($selfCoreFiles | Where-Object { $_ -ne 'scripts/scan.ps1' })) {
    $hp = Join-Path $skillDir ($rel -replace '/', '\')
    if (-not (Test-Path -LiteralPath $hp)) { Write-Output ('错误: 核心文件缺失，无法刷新哈希: ' + $rel); exit 2 }
    $h = (Get-FileHash -Algorithm SHA256 -LiteralPath $hp).Hash
    [void]$lines.Add(("  '" + $rel + "' = '" + $h + "'"))
  }
  [void]$lines.Add('}')
  [void]$lines.Add('# __SELF_HASHES_END__')
  $block = ($lines -join "`r`n")
  $text = [System.IO.File]::ReadAllText($scriptPath, [System.Text.Encoding]::UTF8)
  $rx = [regex]'# __SELF_HASHES_BEGIN__[\s\S]*?# __SELF_HASHES_END__'
  if (-not $rx.IsMatch($text)) { Write-Output '错误: scan.ps1 中缺少哈希标记块，无法刷新'; exit 2 }
  $text = $rx.Replace($text, $block, 1)
  [System.IO.File]::WriteAllText($scriptPath, $text, (New-Object System.Text.UTF8Encoding($true)))
  Write-Output ('自扫哈希已刷新（' + ($selfCoreFiles.Count - 1) + ' 个核心文件，除 scan.ps1 自身）')
}

function Write-RegistryStats {
  # 注册表统计与 regex 编译校验（YAML 解析器独立测试入口）
  $failCount = 0
  foreach ($r in @($registry.rules) + @($registry.hints)) {
    if (-not $r.regex) { continue }
    try { [void][regex]::new([string]$r.regex) } catch { $failCount++; Write-Output ('REGEX_FAIL ' + $r.rule_id + ': ' + $_.Exception.Message) }
  }
  $out = [ordered]@{
    version = 1
    rule_entries = @($registry.rules).Count
    unique_rule_ids = @($registry.rules | ForEach-Object { $_.rule_id } | Sort-Object -Unique).Count
    hints = @($registry.hints).Count
    projections = @($registry.projections).Count
    compile_failures = $failCount
    rules_version = [string]$registry.rules_version
  }
  $content = $out | ConvertTo-Json -Compress
  if ($Output) {
    [System.IO.File]::WriteAllText($Output, $content, (New-Object System.Text.UTF8Encoding($false)))
    Write-Output ('注册表统计已写入: ' + $Output)
  } else {
    Write-Output $content
  }
}

function Get-ExternalScannerExe {
  # 探测外部扫描器可执行文件（aguara / skill-scanner）：显式环境变量优先，缺失返回 $null
  param([string]$Name)
  $envVar = if ($Name -eq 'aguara') { 'SKILLSPECTOR_AGUARA' } else { 'SKILLSPECTOR_SKILL_SCANNER' }
  $explicit = [Environment]::GetEnvironmentVariable($envVar)
  if ($explicit) {
    if (Test-Path -LiteralPath $explicit) { return $explicit }
    return $null
  }
  $g = Get-Command $Name -ErrorAction SilentlyContinue
  if ($g) { return $g.Source }
  return $null
}

function Get-GitExe {
  # 定位 git：PATH 优先，回退 Codex 内置运行时
  $g = Get-Command git -ErrorAction SilentlyContinue
  if ($g) { return $g.Source }
  if ($env:USERPROFILE) {
    $bundled = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\native\git\cmd\git.exe'
    if (Test-Path -LiteralPath $bundled) { return $bundled }
  }
  return $null
}

function Invoke-ExternalScanners {
  # 可选外部扫描器适配层（借鉴 skill-vetter 的多扫描器编排）：自动探测 aguara / skill-scanner，
  # 调用后把命中归一化为 EXT_AGUARA / EXT_SKILLSCANNER 发现并参与计分；缺失 → SKIP，不报错；
  # 输出解析失败 → degraded + 错误条目。-NoExt 关闭本适配层。
  param([string]$root, [System.Collections.ArrayList]$errors, [hashtable]$engines)
  $out = New-Object System.Collections.ArrayList
  if ($NoExt) {
    $engines['external_aguara'] = 'disabled'
    $engines['external_skill_scanner'] = 'disabled'
    return $out
  }
  $aguara = Get-ExternalScannerExe 'aguara'
  $skillScanner = Get-ExternalScannerExe 'skill-scanner'
  $prevEap = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    if ($aguara) {
      $engines['external_aguara'] = 'running'
      $raw = & $aguara scan $root --format json 2>$null
      $code = $LASTEXITCODE
      $text = @($raw) -join ''
      try {
        $obj = $text | ConvertFrom-Json
        foreach ($fd in @($obj.findings)) {
          $sevNum = 0
          try { $sevNum = [double]$fd.severity } catch {}
          if ($sevNum -lt 3) { continue }
          $sev = if ($sevNum -ge 4) { 'HIGH' } else { 'MEDIUM' }
          $fp = [string]$fd.file_path
          if ($fp -and -not [System.IO.Path]::IsPathRooted($fp)) { $fp = Join-Path $root $fp }
          if (-not $fp) { $fp = $root }
          $ln = 0
          try { $ln = [int]$fd.line } catch {}
[void]$out.Add((New-Finding -id 'EXT_AGUARA' -severity $sev -file $fp -line $ln -text (('aguara[' + $fd.rule_id + '] ' + $fd.description)) -context 'code' -doc $false -confidence 'medium' -analyzer 'external'))
        }
        $engines['external_aguara'] = if ($code -ne 0) { 'degraded' } else { 'on' }
      } catch {
        $engines['external_aguara'] = 'degraded'
        [void]$errors.Add('aguara 输出解析失败（退出码 ' + $code + '），其发现未纳入')
      }
    } else {
      $engines['external_aguara'] = 'skipped'
    }
    if ($skillScanner) {
      $engines['external_skill_scanner'] = 'running'
      $raw2 = & $skillScanner scan $root --format json 2>$null
      $code2 = $LASTEXITCODE
      $text2 = @($raw2) -join ''
      try {
        $obj2 = $text2 | ConvertFrom-Json
        $items = @()
        if ($obj2.PSObject.Properties['findings'] -and @($obj2.findings).Count -gt 0) { $items = @($obj2.findings) }
        elseif ($obj2) { $items = @($obj2) }
        foreach ($fd in $items) {
          $sevStr = ([string]$fd.severity).ToLower()
          if ($sevStr -in @('low', 'none', 'unknown', '')) { continue }
          $sev = switch ($sevStr) {
            'critical' { 'HIGH' }; 'high' { 'HIGH' }; 'medium' { 'MEDIUM' }; default { 'LOW' }
          }
          $fp2 = [string]$fd.file
          if ($fp2 -and -not [System.IO.Path]::IsPathRooted($fp2)) { $fp2 = Join-Path $root $fp2 }
          if (-not $fp2) { $fp2 = $root }
          $ln2 = 0
          try { $ln2 = [int]$fd.line } catch {}
          $desc = [string]$fd.description
          if (-not $desc) { $desc = 'skill-scanner 命中（' + $sevStr + '）' }
[void]$out.Add((New-Finding -id 'EXT_SKILLSCANNER' -severity $sev -file $fp2 -line $ln2 -text $desc -context 'code' -doc $false -confidence 'medium' -analyzer 'external'))
        }
        $engines['external_skill_scanner'] = if ($code2 -ne 0) { 'degraded' } else { 'on' }
      } catch {
        $engines['external_skill_scanner'] = 'degraded'
        [void]$errors.Add('skill-scanner 输出解析失败（退出码 ' + $code2 + '），其发现未纳入')
      }
    } else {
      $engines['external_skill_scanner'] = 'skipped'
    }
  } catch {
    [void]$errors.Add('外部扫描器调用失败: ' + $_.Exception.Message)
  } finally {
    $ErrorActionPreference = $prevEap
  }
  return $out
}

function Write-CheckDeps {
  # -CheckDeps：输出各检查器可用性（引擎状态透明化；不联网、不扫描）
  $eng = [ordered]@{
    python_ast = if (Get-PythonExe) { 'available' } else { 'missing' }
    git_history = if (Get-GitExe) { 'available' } else { 'missing' }
    external_aguara = if (Get-ExternalScannerExe 'aguara') { 'available' } else { 'missing' }
    external_skill_scanner = if (Get-ExternalScannerExe 'skill-scanner') { 'available' } else { 'missing' }
    registry = 'loaded (' + [string]$registry.rules_version + ')'
  }
  if ($Json) {
    $content = ([ordered]@{ version = 1; scanner = $scannerVersion; engines = $eng } | ConvertTo-Json -Compress)
    if ($Output) {
      [System.IO.File]::WriteAllText($Output, $content, (New-Object System.Text.UTF8Encoding($false)))
      Write-Output ('依赖检查已写入: ' + $Output)
    } else {
      Write-Output $content
    }
  } else {
    Write-Output ('PowerShell ' + $PSVersionTable.PSVersion.ToString())
    foreach ($k in @($eng.Keys)) { Write-Output (('  {0}: {1}' -f $k, $eng[$k])) }
  }
}

if (-not (Get-RegistryRules)) {
  Write-Output '错误: 规则注册表加载失败（rules/rules.yaml 缺失或解析失败），拒绝运行'
  exit 2
}
if ($RebakeSelfHashes) { Write-SelfHashes; exit 0 }
if ($RegistryStats) { Write-RegistryStats; exit 0 }

function Test-SelfSkill {
  # 自扫豁免三层判定：结构指纹 + 文件集白名单 + 核心文件哈希（scan.ps1 自身哈希无法自嵌，不在校验内）
  # 已知局限：开源无外部信任锚，高对抗整包伪造者仍可复制全部内容；文件集白名单堵住“整包复制+新增文件”绕过
  param([string]$scanPath)
  try {
    if ((Split-Path $scanPath -Leaf) -ne $skillName) { return $false }
    $item = Get-Item -Force -LiteralPath $scanPath -ErrorAction Stop
    if (-not $item.PSIsContainer) { return $false }
    # 1) 结构指纹：SKILL.md frontmatter name + scan.ps1 哨兵常量
    $skillMd = Join-Path $scanPath 'SKILL.md'
    if (-not (Test-Path -LiteralPath $skillMd)) { return $false }
    $nameOk = $false
    foreach ($line in @(Get-Content -Encoding UTF8 -LiteralPath $skillMd -TotalCount 8)) {
      if ($line -match '^name:\s*[''"]?skillspector-scan[''"]?\s*$') { $nameOk = $true; break }
    }
    if (-not $nameOk) { return $false }
    $scanScript = Join-Path $scanPath 'scripts\scan.ps1'
    if (-not (Test-Path -LiteralPath $scanScript)) { return $false }
    if (-not (Get-Content -Raw -Encoding UTF8 -LiteralPath $scanScript).Contains($SelfMarker)) { return $false }
    # 2) 文件集白名单：核心文件集之外出现任何文件 → 不豁免（堵“整包复制+新增恶意文件”绕过）
    $relPaths = @()
    $fixtureManifest = @()
    $mfPath = Join-Path $scanPath 'test\fixtures\MANIFEST.json'
    if (Test-Path -LiteralPath $mfPath) {
      try {
        $mf = Get-Content -Raw -Encoding UTF8 -LiteralPath $mfPath | ConvertFrom-Json
        if ($mf.files) { $fixtureManifest = @($mf.files) }
      } catch { $fixtureManifest = @() }
    }
    foreach ($f in @(Get-ItemsSafe $scanPath)) {
      $rel = $f.FullName.Substring($scanPath.Length).TrimStart('\', '/').Replace('\', '/')
      if ($f.Name -like '.skillspector-baseline*' -or $rel -in @('.skillspector-verified.yaml', '.DS_Store', 'Thumbs.db')) { continue }
      if ($rel -eq 'test/fixtures/MANIFEST.json') { $relPaths += $rel; continue }
      if ($rel -like 'test/fixtures/*') {
        # 官方测试夹具目录：仅接受 MANIFEST 收录的文件（防“新增夹具名义”绕过）
        if ($fixtureManifest -notcontains $rel) { return $false }
        continue
      }
      if ($selfCoreFiles -notcontains $rel) { return $false }
      $relPaths += $rel
    }
    foreach ($core in $selfCoreFiles) {
      if ($relPaths -notcontains $core) { return $false }
    }
    # 3) 哈希白名单：校验除 scan.ps1 外的核心文件；-SelfDev 跳过哈希（保留文件集校验），供开发期使用
    if (-not $SelfDev) {
      foreach ($k in @($SelfHashes.Keys)) {
        $hp = Join-Path $scanPath ($k -replace '/', '\')
        if (-not (Test-Path -LiteralPath $hp)) { return $false }
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath $hp).Hash -ne $SelfHashes[$k]) { return $false }
      }
    }
    return $true
  } catch {
    return $false
  }
}

function Get-SkillsRoot {
  if ($env:CODEX_HOME) { return Join-Path $env:CODEX_HOME 'skills' }
  $here = Split-Path $PSScriptRoot -Parent
  $root = Split-Path $here -Parent
  if ((Split-Path $here -Leaf) -eq $skillName) { return $root }
  return $null
}

function Test-SkillRoot {
  # 轻量技能根检测：目录根存在 SKILL.md 即视为一个 skill（唯一审核单位）
  param([string]$path)
  return (Test-Path -LiteralPath (Join-Path $path 'SKILL.md') -PathType Leaf)
}

function Get-SkillNameFromMd {
  # 读取 SKILL.md frontmatter 的 name 作为展示用技能名；缺失时回退目录名
  param([string]$root)
  $md = Join-Path $root 'SKILL.md'
  if (Test-Path -LiteralPath $md -PathType Leaf) {
    try {
      $head = @(Get-Content -LiteralPath $md -TotalCount 40 -ErrorAction Stop)
      $fm = $head -join "`n"
      if ($fm -match '(?ms)^---\s*\r?\n(.*?)^---') {
        $body = $matches[1]
        if ($body -match '(?mi)^name:\s*(.+?)\s*$') { return $matches[1].Trim() }
      }
    } catch {}
  }
  return (Split-Path $root -Leaf)
}

function Find-SkillRoots {
  # 在给定目录下查找技能根：先查一级子目录，未命中再查二级（仓库/分类目录/技能 布局）
  param([string]$path)
  $roots = New-Object System.Collections.ArrayList
  $c1 = @(Get-ChildItem -Directory -Force -LiteralPath $path -ErrorAction SilentlyContinue |
    Where-Object { -not $_.Name.StartsWith('.') })
  foreach ($d in $c1) { if (Test-SkillRoot $d.FullName) { [void]$roots.Add($d.FullName) } }
  if ($roots.Count -eq 0) {
    foreach ($d in $c1) {
      foreach ($d2 in @(Get-ChildItem -Directory -Force -LiteralPath $d.FullName -ErrorAction SilentlyContinue |
        Where-Object { -not $_.Name.StartsWith('.') })) {
        if (Test-SkillRoot $d2.FullName) { [void]$roots.Add($d2.FullName) }
      }
    }
  }
  return @($roots | Sort-Object)
}

function Get-Targets {
  $list = @()
  $script:PathScopeMode = 'none'
  $modes = 0
  if ($AllInstalled) { $modes++ }
  if ($Path) { $modes++ }
  if ($Dir) { $modes++ }
  if ($modes -gt 1) { throw '请只使用 -Path / -AllInstalled / -Dir 中的一种' }
  if ($AllInstalled) {
    $root = Get-SkillsRoot
    if (-not $root) { throw '无法定位 skills 根目录，请改用 -Path 指定' }
    $list = @(Get-ChildItem -Directory -Force -LiteralPath $root |
      Where-Object { -not $_.Name.StartsWith('.') } | Select-Object -ExpandProperty FullName)
    if ($list.Count -eq 0) { throw "skills 根目录为空: $root" }
  } elseif ($Dir) {
    $dirResolved = (Resolve-Path -LiteralPath $Dir -ErrorAction Stop).Path
    if (-not (Test-Path -LiteralPath $dirResolved -PathType Container)) { throw "路径不是文件夹: $Dir" }
    $list = @(Get-ChildItem -Force -LiteralPath $dirResolved |
      Where-Object { ($_.PSIsContainer -and -not $_.Name.StartsWith('.')) -or ($_.Name -match '(?i)\.zip$') } |
      Sort-Object Name | Select-Object -ExpandProperty FullName)
    if ($list.Count -eq 0) { throw "目录下未发现技能文件夹或 zip: $dirResolved" }
  } elseif ($Path) {
    $resolved = @(Resolve-Path -LiteralPath $Path -ErrorAction Stop)
    $p = $resolved.Path
    if (Test-Path -LiteralPath $p -PathType Container) {
      if (Test-SkillRoot $p) {
        $script:PathScopeMode = 'skill'
        [Console]::Error.WriteLine('Skill root detected: ' + $p)
        $list = @($p)
      } else {
        $nested = @(Find-SkillRoots $p)
        if ($nested.Count -gt 0) {
          if ($nested.Count -eq 1) {
            $script:PathScopeMode = 'skill'
            [Console]::Error.WriteLine('Skill root detected: ' + $nested[0])
          } else {
            $script:PathScopeMode = 'multi-skill'
            [Console]::Error.WriteLine('Warning: This directory contains multiple skills. Security review works best with: one skill = one target.')
            [Console]::Error.WriteLine('Detected skills:')
            foreach ($s in $nested) { [Console]::Error.WriteLine('  * ' + (Split-Path $s -Leaf)) }
            [Console]::Error.WriteLine('→ 已按“1 skill = 1 Target”拆分为 ' + $nested.Count + ' 个独立审核目标')
          }
          $list = @($nested)
        } else {
          $script:PathScopeMode = 'directory'
          [Console]::Error.WriteLine('Warning: not recognized as isolated skill（未识别为独立技能，按单目录扫描）')
          $list = @($p)
        }
      }
    } else {
      $script:PathScopeMode = 'file'
      $list = @($p)
    }
  } else {
    throw '请提供 -Path <技能目录|文件|zip>、-Dir <技能文件夹> 或使用 -AllInstalled'
  }
  return ,$list
}

function Read-TextFile {
  param([string]$path)
  try {
    $fs = [System.IO.File]::OpenRead($path)
  } catch {
    return [pscustomobject]@{ Text = $null; Encoding = ''; Truncated = $false; Status = 'permission_denied' }
  }
  try {
    $len = [Math]::Min([long]$fs.Length, [long]($MaxFileBytes + 1))
    $buf = New-Object byte[] $len
    $read = $fs.Read($buf, 0, $len)
  } finally { $fs.Dispose() }
  if ($read -eq 0) { return $null }
  $truncated = ($read -gt $MaxFileBytes)
  if ($truncated) {
    $tmp = New-Object byte[] $MaxFileBytes
    [Array]::Copy($buf, $tmp, $MaxFileBytes)
    $buf = $tmp
  }
  $enc = 'utf-8'
  $text = $null
  if ($buf.Length -ge 3 -and $buf[0] -eq 0xEF -and $buf[1] -eq 0xBB -and $buf[2] -eq 0xBF) {
    $text = [System.Text.Encoding]::UTF8.GetString($buf, 3, $buf.Length - 3)
  } elseif ($buf.Length -ge 2 -and $buf[0] -eq 0xFF -and $buf[1] -eq 0xFE) {
    $enc = 'utf-16le'
    $text = [System.Text.Encoding]::Unicode.GetString($buf, 2, $buf.Length - 2)
  } elseif ($buf.Length -ge 2 -and $buf[0] -eq 0xFE -and $buf[1] -eq 0xFF) {
    $enc = 'utf-16be'
    $text = [System.Text.Encoding]::BigEndianUnicode.GetString($buf, 2, $buf.Length - 2)
  } else {
    try {
      $strict = New-Object System.Text.UTF8Encoding($false, $true)
      $text = $strict.GetString($buf)
    } catch {
      $enc = 'gbk'
      try {
        $gbk = [System.Text.Encoding]::GetEncoding(936, [System.Text.EncoderFallback]::ExceptionFallback, [System.Text.DecoderFallback]::ExceptionFallback)
        $text = $gbk.GetString($buf)
      }
      catch { return [pscustomobject]@{ Text = $null; Encoding = 'unknown'; Truncated = $truncated; Status = 'unsupported_encoding' } }
    }
  }
  $text = $text -replace "`r`n", "`n" -replace "`r", "`n"
  return [pscustomobject]@{ Text = $text; Encoding = $enc; Truncated = $truncated; Status = 'ok' }
}

function Test-BinaryContent {
  # 内容嗅探：扩展名无法分类时的二进制判定（含 NUL 字节 → 二进制；UTF-16 BOM 不误判）
  param([string]$path)
  try {
    $fs = [System.IO.File]::OpenRead($path)
    try {
      $len = [Math]::Min([long]$fs.Length, 8192)
      if ($len -eq 0) { return $false }
      $buf = New-Object byte[] $len
      $read = $fs.Read($buf, 0, $len)
      if ($read -ge 2 -and (($buf[0] -eq 0xFF -and $buf[1] -eq 0xFE) -or ($buf[0] -eq 0xFE -and $buf[1] -eq 0xFF))) { return $false }
      for ($i = 0; $i -lt $read; $i++) { if ($buf[$i] -eq 0) { return $true } }
      return $false
    } finally { $fs.Dispose() }
  } catch { return $false }
}

function Get-IpCandidates {
  # 从一行文本提取 IPv4 / IPv6 地址候选（IPv6 采用简化匹配，避免误伤 http:// 等）
  param([string]$line)
  $out = New-Object System.Collections.ArrayList
  $ipv4Re = '\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b'
  foreach ($m in [regex]::Matches($line, $ipv4Re)) { [void]$out.Add($m.Value) }
  $ipv6Re = '(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b|(?<![\w:])::1(?![\w:])|\bf[cd]00::[0-9a-f:]+\b|\bfe80::[0-9a-f:]+\b'
  foreach ($m in [regex]::Matches($line, $ipv6Re)) { [void]$out.Add($m.Value) }
  return ,@($out | Select-Object -Unique)
}

function Get-AddressClass {
  # 地址分类器：IPv4 / IPv6 → loopback / private / link-local / public / unknown
  param([string]$addr)
  $a = $addr.Trim().TrimEnd('.').ToLowerInvariant()
  if ($a -match '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$') {
    $o1 = [int]$matches[1]; $o2 = [int]$matches[2]
    if ($o1 -eq 127) { return 'loopback' }
    if ($o1 -eq 10) { return 'private' }
    if ($o1 -eq 192 -and $o2 -eq 168) { return 'private' }
    if ($o1 -eq 172 -and $o2 -ge 16 -and $o2 -le 31) { return 'private' }
    if ($o1 -eq 169 -and $o2 -eq 254) { return 'link-local' }
    return 'public'
  }
  if ($a -eq '::1') { return 'loopback' }
  if ($a -like 'fe80::*') { return 'link-local' }
  if ($a -like 'fc*' -or $a -like 'fd*') { return 'private' }
  if ($a -match ':') { return 'public' }
  return 'unknown'
}

function Get-ContextForFile {
  param([System.IO.FileInfo]$fi, [string]$root)
  $ext = $fi.Extension.ToLower()
  $name = $fi.Name.ToLower()
  $rel = $fi.FullName.Substring($root.Length).TrimStart('\', '/')
  if ($name -like '.env*' -or $name -match '^(requirements.*\.txt|Pipfile|environment\.ya?ml|pyproject\.toml)$') { return 'config' }
  if ($ext -in @('.md','.markdown','.rst') -or $name -eq 'readme' -or $name.StartsWith('readme.')) { return 'doc' }
  if ($ext -in @('.yaml','.yml','.json','.toml','.xml','.ini','.cfg','.conf','.editorconfig','.gitignore','.gitattributes','.dockerignore','.svg','.lock')) { return 'config' }
  if ($ext -in @('.py','.js','.mjs','.cjs','.ts','.tsx','.jsx','.sh','.bash','.ps1','.psm1','.psd1','.bat','.cmd','.rb','.pl','.lua','.go','.rs','.c','.cpp','.h','.java','.kt','.php','.swift','.sql')) { return 'code' }
  return 'data'
}

function Get-FenceLines {
  param([string[]]$lines)
  $set = @{}
  $inFence = $false
  for ($i = 0; $i -lt $lines.Count; $i++) {
    $t = $lines[$i].Trim()
    if ($t -match '^(`{3,}|~{3,})') {
      $inFence = -not $inFence
      $set[$i + 1] = $true
    } elseif ($inFence) {
      $set[$i + 1] = $true
    }
  }
  return $set
}

function Get-LineNumber {
  param([string]$text, [int]$index)
  if ($index -le 0) { return 1 }
  return 1 + ([regex]::Matches($text.Substring(0, $index), "`n")).Count
}

function Get-ItemsSafe {
  # 安全枚举：BFS 遍历目录，不进入符号链接/联接（防循环目录卡死与越界读取）
  param([string]$root, [switch]$IncludeDirs, [System.Collections.ArrayList]$errors = $null)
  $out = New-Object System.Collections.ArrayList
  $item = Get-Item -Force -LiteralPath $root -ErrorAction SilentlyContinue
  if (-not $item) { return $out }
  $queue = New-Object System.Collections.Queue
  $queue.Enqueue($item)
  while ($queue.Count -gt 0) {
    $dir = $queue.Dequeue()
    $children = $null
    try {
      $children = @(Get-ChildItem -Force -LiteralPath $dir.FullName -ErrorAction Stop)
    } catch {
      if ($errors) { [void]$errors.Add([pscustomobject]@{ path = $dir.FullName; reason = 'permission_denied' }) }
      continue
    }
    foreach ($child in $children) {
      if ($child.PSIsContainer) {
        if ($child.LinkType) {
          if ($IncludeDirs) { [void]$out.Add($child) }
          continue
        }
        if ($IncludeDirs) { [void]$out.Add($child) }
        $queue.Enqueue($child)
      } else {
        [void]$out.Add($child)
      }
    }
  }
  return $out
}

function New-Evidence {
  # 统一 Evidence 对象：事实层最小单元；observed 与 finding.text 一致（masked），避免敏感值外泄
  param([string]$targetId, [string]$inspectionId, [string]$ruleId, [string]$file,
        [int]$lineStart = 0, [int]$lineEnd = 0, [string]$evidenceType = 'pattern',
        [string]$extractor = 'regex', [string]$observed = '', [string]$normalized = '',
        [string]$strength = 'E1', [string]$origin = 'native',
        [string]$engine = '', [string]$sourceType = '', [string[]]$parentEvidenceIds = @())
  $idInput = [ordered]@{
    target = $targetId; inspection = $inspectionId; rule = $ruleId; file = $file
    line = $lineStart; type = $evidenceType; extractor = $extractor
    observed = $observed; strength = $strength; origin = $origin
  }
  $eid = (Get-Sha256Hex (ConvertTo-CanonicalJson $idInput)).Substring(0, 24)
  return [pscustomobject]@{
    evidence_id = $eid
    target_id = $targetId
    inspection_id = $inspectionId
    rule_id = $ruleId
    file = $file
    line_start = $lineStart
    line_end = if ($lineEnd -gt 0) { $lineEnd } else { $lineStart }
    byte_start = $null
    byte_end = $null
    evidence_type = $evidenceType
    extractor = $extractor
    observed = $observed
    normalized = $normalized
    content_hash = Get-Sha256Hex $observed
    evidence_strength = $strength
    lifecycle = 'observed'
    origin = $origin
    provenance = [pscustomobject]@{
      target_id = $targetId
      inspection_id = $inspectionId
      engine = $(if ($engine) { $engine } else { $extractor })
      extractor = $extractor
      rule_id = $ruleId
      source_type = $sourceType
      parent_evidence_ids = @($parentEvidenceIds)
    }
  }
}

function New-Finding {
  param($id, $severity, $file, $line, $text, $context, $doc, $score = $true,
        [int]$column = 0, [string]$activity = 'unknown', [string]$invocation = 'unknown',
        [string]$execution = 'unknown', [string]$confidence = 'medium', [string]$sourceId = '',
        [string[]]$evidenceRefs = @(), [string]$analyzer = '')
  $masked = Get-MaskedText $text
  $obj = [pscustomobject]@{
    finding_id = ''
    id       = $id
    desc     = if ($descMap.ContainsKey($id)) { $descMap[$id] } else { Get-RuleDesc $id }
    owasp    = if ($owaspMap.ContainsKey($id)) { $owaspMap[$id] } else { '' }
    severity = $severity
    file     = $file
    line     = $line
    column   = $column
    text     = $masked
    context  = $context
    doc      = [bool]$doc
    score    = [bool]$score
    activity = $activity
    invocation = $invocation
    execution = $execution
    confidence = $confidence
    source_finding_id = @()
    evidence_refs = @($evidenceRefs)
    analyzer = $analyzer
  }
  if ($sourceId) { $obj.source_finding_id = @($sourceId) }
  $idInput = [ordered]@{ id = $id; severity = $severity; file = $file; line = $line; column = $column; text = $masked; context = $context; activity = $activity; invocation = $invocation; execution = $execution; confidence = $confidence }
  $obj.finding_id = (Get-Sha256Hex (ConvertTo-CanonicalJson $idInput)).Substring(0, 24)
  return $obj
}

function Get-MaskedText {
  param([string]$text)
  $t = $text
  $t = [regex]::Replace($t, '(sk-[A-Za-z0-9_\-]{6})[A-Za-z0-9_\-]+', '$1***')
  $t = [regex]::Replace($t, '(ghp_[A-Za-z0-9]{6})[A-Za-z0-9]+', '$1***')
  $t = [regex]::Replace($t, '(AKIA[0-9A-Z]{6})[0-9A-Z]+', '$1***')
  $t = [regex]::Replace($t, '(xox[baprs]-[A-Za-z0-9\-]{6})[A-Za-z0-9\-]+', '$1***')
  $t = [regex]::Replace($t, '(--BEGIN[^-]+PRIVATE\s+KEY-----).*', '$1***')
  $t = [regex]::Replace($t, '((?:API_KEY|SECRET|TOKEN|PASSWORD|PASSWD|PWD)\s*=\s*[\x22\x27]?)[^\s\x22\x27&,]+', '$1***')
  return $t
}

function Test-Base64Payload {
  param([string]$text, [string]$file, [string]$context, [bool]$doc)
  $out = New-Object System.Collections.ArrayList
  $rx = [regex]'[A-Za-z0-9+/]{64,}={0,2}'
  $danger = @('exec(','eval(','subprocess','os.system','powershell','cmd.exe','/bin/sh','Invoke-Expression','curl','wget','python','perl')
  foreach ($m in $rx.Matches($text)) {
    $clean = $m.Value -replace '\s', ''
    if ($clean.Length -lt 64) { continue }
    try { $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($clean)) }
    catch { continue }
    $hit = $null
    foreach ($d in $danger) {
      if ($decoded.IndexOf($d, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { $hit = $d; break }
    }
    if ($hit) {
      $ln = Get-LineNumber $text $m.Index
[void]$out.Add((New-Finding -id 'OBS' -severity 'HIGH' -file $file -line $ln -text ('base64 载荷解码后含危险关键词: ' + $hit) -context $context -doc $doc -analyzer 'base64'))
    }
  }
  return $out
}

function Get-EnvCredentialFindings {
  param([string]$root)
  $out = New-Object System.Collections.ArrayList
  foreach ($envFile in @(Get-ItemsSafe $root)) {
    if ($envFile.Name -notlike '.env*' -or $envFile.Name -like '.skillspector*') { continue }
    $lines = @(Get-Content -Encoding UTF8 -LiteralPath $envFile.FullName -ErrorAction SilentlyContinue)
    for ($i = 0; $i -lt $lines.Count; $i++) {
      $l = $lines[$i]
      if ($l -match '^\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*\S' -and $l -notmatch '^\s*#') {
        $name = ($l -split '=')[0].Trim()
        $val = (($l -split '=', 2)[1]).Trim().Trim('"', "'")
        if (-not $val) { continue }
        if ($val -in @('xxx', 'sk-xxx') -or $val -match '^(your_|YOUR_|placeholder|example|changeme|<)') { continue }
        # 只把“名称像密钥”或“值像密钥”的项标为凭据，普通配置（如模型名、URL）不算
        $secretName = $name -match '(?i)(api[_-]?key|secret|token|passw(or)?d|credential|auth|access[_-]?key|private[_-]?key)'
        $secretValue = $val -match '(?i)(sk-[a-z0-9]{16,}|ghp_[a-z0-9]{30,}|akia[0-9a-z]{16}|xox[baprs]-|-----begin[^-]+private\s+key-----)'
        if (-not ($secretName -or $secretValue)) { continue }
[void]$out.Add((New-Finding -id 'CRED' -severity 'HIGH' -file $envFile.FullName -line ($i + 1) -text ('.env 含疑似凭据变量: ' + $name + '（值已隐藏）') -context 'config' -doc $false -analyzer 'env'))
      }
    }
  }
  return $out
}

function Get-MetaFindings {
  param([string]$root)
  $out = New-Object System.Collections.ArrayList
  foreach ($metaFile in @(Get-ItemsSafe $root)) {
    if ($metaFile.Name -ne 'SKILL.md') { continue }
    $content = Read-TextFile $metaFile.FullName
    $head = @()
    if ($content) { $head = @($content.Text -split "`n" | Select-Object -First 30) }
    $okFence = $false; $okName = $false; $okDesc = $false; $nameVal = $null
    if ($head.Count -gt 0 -and $head[0].Trim() -eq '---') {
      for ($i = 1; $i -lt $head.Count; $i++) {
        if ($head[$i].Trim() -eq '---') { $okFence = $true; break }
        if ($head[$i] -match '^name:\s*(.+)$') { $nameVal = $matches[1].Trim(); $okName = $true }
        if ($head[$i] -match '^description:\s*\S') { $okDesc = $true }
      }
    }
    $folder = Split-Path $metaFile.DirectoryName -Leaf
    if (-not $okFence -or -not $okName -or -not $okDesc) {
[void]$out.Add((New-Finding -id 'MD' -severity 'LOW' -file $metaFile.FullName -line 1 -text 'frontmatter 不完整（缺 name/description 或缺少 --- 包裹）' -context 'doc' -doc $false -analyzer 'meta'))
    } elseif ($nameVal -ne $folder) {
[void]$out.Add((New-Finding -id 'MD' -severity 'LOW' -file $metaFile.FullName -line 1 -text ("name 与目录名不一致: $nameVal != $folder") -context 'doc' -doc $false -analyzer 'meta'))
    }
  }
  return $out
}

function Get-LinkFindings {
  param([string]$root)
  $out = New-Object System.Collections.ArrayList
  $normRoot = [System.IO.Path]::GetFullPath($root).TrimEnd('\', '/') + '\'
  foreach ($link in @(Get-ItemsSafe $root -IncludeDirs)) {
    if (-not $link.LinkType) { continue }
    $target = [string]$link.Target
    if ($target -and -not [System.IO.Path]::IsPathRooted($target)) {
      try { $target = [System.IO.Path]::GetFullPath((Join-Path $link.DirectoryName $target)) } catch {}
    }
    if ($target) {
      $normTarget = $target.TrimEnd('\', '/') + '\'
      if ($normTarget.StartsWith($normRoot, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
[void]$out.Add((New-Finding -id 'SYMLINK' -severity 'MED' -file $link.FullName -line 0 -text ('符号链接/联接指向技能目录外: -> ' + $target) -context 'data' -doc $false -analyzer 'link'))
    }
  }
  return $out
}

function Get-PythonExe {
  $candidates = New-Object System.Collections.ArrayList
  if ($Python) { [void]$candidates.Add($Python) }
  foreach ($c in @('python', 'python3')) {
    $g = Get-Command $c -ErrorAction SilentlyContinue
    if ($g) { [void]$candidates.Add($g.Source) }
  }
  if ($env:USERPROFILE) {
    $bundled = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
    [void]$candidates.Add($bundled)
  }
  foreach ($c in @($candidates | Select-Object -Unique)) {
    if (-not (Test-Path -LiteralPath $c)) { continue }
    & $c -c 'pass' 2>$null
    if ($LASTEXITCODE -eq 0) { return $c }
  }
  return $null
}

function Invoke-AstCheck {
  param([string[]]$pyFiles, [System.Collections.ArrayList]$errors, [string]$targetId = '', [string]$sourceType = '')
  $out = New-Object System.Collections.ArrayList
  $astEvidence = New-Object System.Collections.ArrayList
  $skippedFiles = New-Object System.Collections.ArrayList
  $py = Get-PythonExe
  if (-not $py) {
    [void]$errors.Add('未找到 Python，AST 分析已跳过（仅正则扫描）')
    return [pscustomobject]@{ Findings = $out; Evidence = $astEvidence; SkippedFiles = $skippedFiles }
  }
  $prevEap = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  $env:PYTHONIOENCODING = 'utf-8'
  try {
    for ($i = 0; $i -lt $pyFiles.Count; $i += 40) {
      $end = [Math]::Min($i + 39, $pyFiles.Count - 1)
      $chunk = $pyFiles[$i..$end]
      $raw = & $py -X utf8 $astScript @chunk 2>$null
      $pyCode = $LASTEXITCODE
      $raw = @($raw) -join ''
      if ($raw) {
        try {
          $obj = $raw | ConvertFrom-Json
          foreach ($fd in @($obj.findings)) {
            $evId = ''
            if ($targetId) {
              $inspId = (Get-Sha256Hex (ConvertTo-CanonicalJson ([ordered]@{ target = $targetId; engine = 'python_ast'; rule = $fd.id; scanner = $scannerVersion }))).Substring(0, 24)
              $ev = New-Evidence -targetId $targetId -inspectionId $inspId -ruleId $fd.id -file $fd.file -lineStart ([int]$fd.line) -evidenceType 'ast' -extractor 'python_ast' -observed ([string]$fd.text) -strength 'E2' -origin 'native' -engine 'python_ast' -sourceType $sourceType
              [void]$astEvidence.Add($ev)
              $evId = $ev.evidence_id
            }
            [void]$out.Add((New-Finding -id $fd.id -severity $fd.sev -file $fd.file -line $fd.line -text $fd.text -context 'code' -doc $false -evidenceRefs $(if ($evId) { @($evId) } else { @() }) -analyzer 'python_ast'))
          }
          foreach ($sk in @($obj.skips)) {
            if ($sk.file) {
              [void]$errors.Add(('AST 跳过 ' + $sk.file + ':' + $sk.line + ' ' + $sk.reason))
              [void]$skippedFiles.Add($sk.file)
            }
          }
        } catch {
          [void]$errors.Add('AST 输出解析失败（退出码 ' + $pyCode + '）: ' + $_.Exception.Message)
          foreach ($cf in $chunk) { [void]$skippedFiles.Add($cf) }
        }
      } elseif ($pyCode -ne 0) {
        [void]$errors.Add('AST 分析器异常退出（退出码 ' + $pyCode + '，无输出，发现可能不完整）')
        foreach ($cf in $chunk) { [void]$skippedFiles.Add($cf) }
      }
    }
  } catch {
    [void]$errors.Add('AST 分析失败: ' + $_.Exception.Message)
    foreach ($cf in $pyFiles) { [void]$skippedFiles.Add($cf) }
  } finally {
    $ErrorActionPreference = $prevEap
  }
  return [pscustomobject]@{ Findings = $out; Evidence = $astEvidence; SkippedFiles = $skippedFiles }
}

function Expand-SafeZip {
  param([string]$zip, [string]$dest, [System.Collections.ArrayList]$errors)
  Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
  $archive = $null
  try {
    $archive = [System.IO.Compression.ZipFile]::OpenRead($zip)
    if ($archive.Entries.Count -gt 10000) { throw ('zip 成员数超过上限 10000: ' + $archive.Entries.Count) }
    $total = [long]0
    foreach ($e in $archive.Entries) {
      $total += $e.Length
      if ($total -gt 100MB) { throw 'zip 解压总大小超过 100MB 上限' }
      $name = ($e.FullName -replace '\\', '/').TrimStart('/')
      if ($name -eq '' -or $name -match '(^|/)\.\.(/|$)' -or $name -match '^[A-Za-z]:') { throw ('zip 含不安全路径条目: ' + $e.FullName) }
      if ($e.FullName.EndsWith('/')) { continue }
      $destFile = Join-Path $dest $name
      $destDir = Split-Path $destFile -Parent
      if (-not (Test-Path -LiteralPath $destDir)) { New-Item -ItemType Directory -Force -Path $destDir | Out-Null }
      [System.IO.Compression.ZipFileExtensions]::ExtractToFile($e, $destFile, $true)
    }
  } catch {
    [void]$errors.Add('zip 解压失败: ' + $_.Exception.Message)
    throw
  } finally {
    if ($archive) { $archive.Dispose() }
  }
}

function Get-Fingerprint {
  param([string]$id, [string]$relPath, [int]$line, [string]$text)
  $raw = $id + '|' + $relPath + '|' + $line + '|' + $text
  $md5 = [System.Security.Cryptography.MD5]::Create()
  try {
    $hash = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($raw))
    return [System.BitConverter]::ToString($hash).Replace('-', '').Substring(0, 12).ToLower()
  } finally { $md5.Dispose() }
}

function Read-Baseline {
  param([string]$path)
  $fp = @{}
  $manifests = @{}
  if (-not (Test-Path -LiteralPath $path)) { return [pscustomobject]@{ Fp = $fp; Manifests = $manifests } }
  $entries = New-Object System.Collections.ArrayList
  $cur = $null
  $inManifests = $false
  $manCur = $null
  foreach ($line in @(Get-Content -Encoding UTF8 -LiteralPath $path)) {
    $t = $line.Trim()
    if ($t -eq '' -or $t.StartsWith('#')) { continue }
    if ($t -eq 'manifests:') { $inManifests = $true; continue }
    if ($inManifests) {
      if ($t -match '^-\s*file:\s*(.+)$') {
        if ($manCur) { [void]$manifests.Add($manCur.file, $manCur.hash) }
        $manCur = @{ file = $matches[1].Trim(); hash = '' }
      } elseif ($manCur -and $t -match '^hash:\s*(\S+)') {
        $manCur.hash = $matches[1]
      } elseif ($t -match '^-\s*id:') {
        $inManifests = $false
      }
      continue
    }
    if ($t -match '^-\s*id:\s*(\S+)') {
      if ($cur) { [void]$entries.Add($cur) }
      $cur = @{ id = $matches[1] }
    } elseif ($cur -and $t -match '^(file|line|fingerprint):\s*(.+)$') {
      $cur[$matches[1]] = $matches[2].Trim()
    }
  }
  if ($cur) { [void]$entries.Add($cur) }
  if ($manCur) { [void]$manifests.Add($manCur.file, $manCur.hash) }
  foreach ($e in $entries) {
    if ($e.ContainsKey('fingerprint')) { $fp[$e['fingerprint']] = $true }
  }
  return [pscustomobject]@{ Fp = $fp; Manifests = $manifests }
}

function Write-BaselineFile {
  param([string]$path, $findings, [string]$root)
  $sb = New-Object System.Text.StringBuilder
  [void]$sb.AppendLine('# skillspector-scan baseline（自动生成，请勿随意手工编辑）')
  [void]$sb.AppendLine('# 生成时间: ' + (Get-Date -Format o))
  [void]$sb.AppendLine('version: 1')
  [void]$sb.AppendLine('findings:')
  foreach ($f in $findings) {
    $rel = $f.file.Substring($root.Length).TrimStart('\', '/')
    $fp = Get-Fingerprint $f.id $rel $f.line $f.text
    [void]$sb.AppendLine('- id: ' + $f.id)
    [void]$sb.AppendLine('  file: ' + $rel)
    [void]$sb.AppendLine('  line: ' + $f.line)
    [void]$sb.AppendLine('  fingerprint: ' + $fp)
  }
  $manifestFiles = @(Get-ItemsSafe $root | Where-Object { $_.Name -in @('SKILL.md','mcp.json','mcp_servers.json','.mcp.json') -or $_.FullName -match '\\agents\\.*\.(yaml|yml|json)$' })
  [void]$sb.AppendLine('manifests:')
  foreach ($mf in $manifestFiles) {
    $rel = $mf.FullName.Substring($root.Length).TrimStart('\', '/')
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $mf.FullName).Hash
    [void]$sb.AppendLine('- file: ' + $rel)
    [void]$sb.AppendLine('  hash: ' + $hash)
  }
  $dir = Split-Path $path -Parent
  if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
  [System.IO.File]::WriteAllText($path, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
}

function Get-ManifestChangeFindings {
  param([string]$root)
  $out = New-Object System.Collections.ArrayList
  if (-not $global:baselineManifests -or $global:baselineManifests.Count -eq 0) { return $out }
  $manifestFiles = @(Get-ItemsSafe $root | Where-Object { $_.Name -in @('SKILL.md','mcp.json','mcp_servers.json','.mcp.json') -or $_.FullName -match '\\agents\\.*\.(yaml|yml|json)$' })
  foreach ($mf in $manifestFiles) {
    $rel = $mf.FullName.Substring($root.Length).TrimStart('\', '/')
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $mf.FullName).Hash
    if ($global:baselineManifests.ContainsKey($rel)) {
      if ($hash -ne $global:baselineManifests[$rel]) {
[void]$out.Add((New-Finding -id 'RP' -severity 'MED' -file $mf.FullName -line 0 -text ('manifest 自上次扫描发生变化（rug-pull 风险）: ' + $rel) -context 'config' -doc $false -analyzer 'manifest'))
      }
    } else {
[void]$out.Add((New-Finding -id 'RP' -severity 'LOW' -file $mf.FullName -line 0 -text ('新增 manifest 文件（未在基线中）: ' + $rel) -context 'config' -doc $false -analyzer 'manifest'))
    }
  }
  return $out
}

function Get-GitHistoryFindings {
  param([string]$root, [System.Collections.ArrayList]$errors)
  $out = New-Object System.Collections.ArrayList
  if (-not $GitHistory) { return $out }
  $git = Get-GitExe
  if (-not $git) { [void]$errors.Add('未找到 git，git 历史扫描已跳过'); return $out }
  if (-not (Test-Path -LiteralPath (Join-Path $root '.git'))) { return $out }
  $prevEap = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    $lines = & $git -C $root log --all -p -n $GitDepth 2>$null
    $secRe = 'sk-[A-Za-z0-9_\-]{20,}|ghp_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|-----BEGIN[^-]+PRIVATE\s+KEY-----|xox[baprs]-[A-Za-z0-9\-]{20,}'
    $seenSecret = @{}
    foreach ($line in $lines) {
      foreach ($m in [regex]::Matches($line, $secRe)) {
        $key = $m.Value
        if ($seenSecret.ContainsKey($key)) { continue }
        $seenSecret[$key] = $true
[void]$out.Add((New-Finding -id 'CRED' -severity 'HIGH' -file (Join-Path $root '.git 历史') -line 0 -text ('git 历史含疑似密钥: ' + (Get-MaskedText $m.Value)) -context 'data' -doc $false -analyzer 'git'))
      }
    }
  } catch {
    [void]$errors.Add('git 历史扫描失败: ' + $_.Exception.Message)
  } finally {
    $ErrorActionPreference = $prevEap
  }
  return $out
}

function Invoke-ParallelScans {
  param([string[]]$targetList, [string]$script)
  $results = New-Object System.Collections.ArrayList
  $queue = New-Object System.Collections.Queue
  foreach ($t in $targetList) { $queue.Enqueue($t) }
  $jobs = @{}
  $jobSb = {
    param($jobArgs)
    try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
    $OutputEncoding = [System.Text.Encoding]::UTF8
    $policyOk = $true
    try { Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction Stop } catch { $policyOk = $false }
    if ($policyOk) {
      $ht = @{}
      $i = 1
      while ($i -lt $jobArgs.Count) {
        $token = [string]$jobArgs[$i]
        if ($token.StartsWith('-')) {
          $name = $token.TrimStart('-')
          if ($i + 1 -lt $jobArgs.Count -and -not ([string]$jobArgs[$i + 1]).StartsWith('-')) {
            $ht[$name] = $jobArgs[$i + 1]
            $i += 2
          } else {
            $ht[$name] = $true
            $i++
          }
        } else { $i++ }
      }
      & $jobArgs[0] @ht
    } else {
      # 跨平台 worker shell：容器内没有 powershell，优先 pwsh
      $worker = if (Get-Command pwsh -ErrorAction SilentlyContinue) { 'pwsh' } else { 'powershell' }
      & $worker -NoProfile -ExecutionPolicy Bypass -File $jobArgs[0] @($jobArgs[1..($jobArgs.Count - 1)])
    }
  }
  while ($jobs.Count -lt 4 -and $queue.Count -gt 0) {
    $t = $queue.Dequeue()
    $ja = Build-WorkerArgs $t
    $j = Start-Job -ScriptBlock $jobSb -ArgumentList (,$ja)
    $jobs[$j.Id] = [pscustomobject]@{ job = $j; target = $t }
  }
  while ($jobs.Count -gt 0) {
    $done = @($jobs.Values | Where-Object { $_.job.State -notin @('Running', 'Blocked') })
    if ($done.Count -eq 0) { Start-Sleep -Milliseconds 250; continue }
    foreach ($d in $done) {
      $raw = @(Receive-Job -Job $d.job -ErrorAction SilentlyContinue)
      Remove-Job -Job $d.job -Force
      $jobs.Remove($d.job.Id)
      $json = ($raw -join "`n").Trim()
      if ($json) {
        try {
          $r = $json | ConvertFrom-Json
          [void]$results.Add([pscustomobject]@{
            path = $r.path; root = $r.root; score = [int]$r.score; severity = $r.severity; recommendation = $r.recommendation;
            hasExecutable = [bool]$r.hasExecutable; findings = @($r.findings); suppressed = @($r.suppressed);
            dependencies = @($r.dependencies); skipped = @($r.skipped); errors = @($r.errors);
            severityCounts = $r.severityCounts; topCategories = @($r.topCategories); topFindings = @($r.topFindings);
            analysis_status = $r.analysis_status; reference_findings = @($r.reference_findings);
            correlation_findings = @($r.correlation_findings); dependency_findings = @($r.dependency_findings);
            behavior_summary = @($r.behavior_summary); top3 = @($r.top3); verification = $r.verification;
            engines = $r.engines
          })
        } catch {
          [void]$results.Add([pscustomobject]@{ path = $d.target; root = $d.target; score = 0; severity = 'LOW'; recommendation = '扫描失败'; hasExecutable = $false; findings = @(); suppressed = @(); dependencies = @(); skipped = @(); errors = @('并行任务输出解析失败: ' + $_.Exception.Message); analysis_status = 'partial'; reference_findings = @(); correlation_findings = @(); dependency_findings = @(); behavior_summary = @(); top3 = @(); verification = [pscustomobject]@{ status = 'none'; decision = ''; date = '' }; engines = [pscustomobject]@{} })
        }
      } else {
        [void]$results.Add([pscustomobject]@{ path = $d.target; root = $d.target; score = 0; severity = 'LOW'; recommendation = '扫描失败'; hasExecutable = $false; findings = @(); suppressed = @(); dependencies = @(); skipped = @(); errors = @('并行任务无输出（可能启动失败）'); analysis_status = 'partial'; reference_findings = @(); correlation_findings = @(); dependency_findings = @(); behavior_summary = @(); top3 = @(); verification = [pscustomobject]@{ status = 'none'; decision = ''; date = '' }; engines = [pscustomobject]@{} })
      }
      if ($queue.Count -gt 0) {
        $t2 = $queue.Dequeue()
        $ja2 = Build-WorkerArgs $t2
        $j2 = Start-Job -ScriptBlock $jobSb -ArgumentList (,$ja2)
        $jobs[$j2.Id] = [pscustomobject]@{ job = $j2; target = $t2 }
      }
    }
  }
  return $results
}

function Build-WorkerArgs {
  param([string]$target)
  $args = New-Object System.Collections.ArrayList
  [void]$args.Add($scriptPath)
  [void]$args.Add('-Path'); [void]$args.Add($target)
  [void]$args.Add('-Json'); [void]$args.Add('-Worker')
  [void]$args.Add('-MaxFileBytes'); [void]$args.Add($MaxFileBytes)
  if ($Baseline) {
    $blAbs = (Resolve-Path -LiteralPath $Baseline -ErrorAction SilentlyContinue).Path
    if ($blAbs) { [void]$args.Add('-Baseline'); [void]$args.Add($blAbs) }
  }
  if ($CheckCVE) { [void]$args.Add('-CheckCVE') }
  if ($GitHistory) { [void]$args.Add('-GitHistory'); [void]$args.Add('-GitDepth'); [void]$args.Add($GitDepth) }
  if ($Python) { [void]$args.Add('-Python'); [void]$args.Add($Python) }
  if ($NoAst) { [void]$args.Add('-NoAst') }
  if ($Brief) { [void]$args.Add('-Brief') }
  if ($Score) { [void]$args.Add('-Score') }
  return ,@($args.ToArray())
}

function Invoke-OsvCheck {
  param($cveCandidates, [System.Collections.ArrayList]$errors)
  $out = New-Object System.Collections.ArrayList
  if (-not $CheckCVE -or $cveCandidates.Count -eq 0) { return $out }
  for ($i = 0; $i -lt $cveCandidates.Count; $i += 100) {
    $end = [Math]::Min($i + 99, $cveCandidates.Count - 1)
    $chunk = $cveCandidates[$i..$end]
    $qs = foreach ($c in $chunk) {
      '{"package":{"name":"' + $c.name + '","ecosystem":"' + $c.eco + '"},"version":"' + $c.version + '"}'
    }
    $body = '{"queries":[' + ($qs -join ',') + ']}'
    try {
      $resp = Invoke-RestMethod -Uri 'https://api.osv.dev/v1/querybatch' -Method Post -ContentType 'application/json' -Body $body -TimeoutSec 25
      for ($j = 0; $j -lt $chunk.Count; $j++) {
        $res = $resp.results[$j]
        if ($res -and $res.vulns) {
          $ids = @($res.vulns | ForEach-Object { $_.id } | Select-Object -First 3) -join ', '
          $c = $chunk[$j]
[void]$out.Add((New-Finding -id 'SC4' -severity 'HIGH' -file $c.file -line $c.line -text ("已知漏洞依赖: $($c.name)==$($c.version) → $ids") -context 'config' -doc $false -analyzer 'osv'))
        }
      }
    } catch {
      [void]$errors.Add('OSV 查询不可用（离线或网络受限），SC4 已跳过: ' + $_.Exception.Message)
      break
    }
  }
  return $out
}

function Invoke-ScanPath {
  param([string]$scanPath, [string]$displayPath)
  $isSkill = Test-SkillRoot $scanPath
  $targetType = 'file'
  if ($isSkill) { $targetType = 'skill' }
  elseif (Test-Path -LiteralPath $scanPath -PathType Container) { $targetType = 'directory' }
  # 注意：不得命名为 $skillName——脚本级 $skillName 是技能 ID，动态作用域下会被此局部变量遮蔽，破坏 Get-SkillsRoot 定位
  $skillDisplayName = ''
  if ($isSkill) { $skillDisplayName = Get-SkillNameFromMd $scanPath }
  $result = [ordered]@{
    path = $displayPath; root = $scanPath; target_type = $targetType; skill_name = $skillDisplayName;
    score = 0; severity = 'LOW'; recommendation = '';
    hasExecutable = $false; findings = @(); suppressed = @(); dependencies = @(); skipped = @(); errors = @();
    analysis_status = 'complete'; scan_files = @(); skip_reasons = @(); reference_findings = @();
    correlation_findings = @(); dependency_findings = @(); behavior_summary = @(); top3 = @();
    verification = [pscustomobject]@{ status = 'none'; decision = ''; date = '' }
  }
  $findings = New-Object System.Collections.ArrayList
  $suppressed = New-Object System.Collections.ArrayList
  $skipped = New-Object System.Collections.ArrayList
  $errors = New-Object System.Collections.ArrayList
  $self = Test-SelfSkill $scanPath
  $targetId = (Get-TargetIdentity $scanPath).identity
  $sourceType = if ($targetType -eq 'skill') { 'directory' } else { $targetType }
  $evidencePool = New-Object System.Collections.ArrayList
  $evidenceSeen = @{}
  $inspectionCache = @{}
  $briefMode = $Brief -or ($env:SKILLSPECTOR_BRIEF -eq '1')
  $root = $scanPath
  $allFiles = @()
  $hasExec = $false
  $cveCandidates = New-Object System.Collections.ArrayList
  $baselineFp = @{}
  if ($global:baselineFp) { $baselineFp = $global:baselineFp }
  $fileStatus = @{}
  $skipReasons = @{}
  $engines = @{
    regex = 'on'; multi = 'on'; lexer = 'skipped'; python_ast = 'skipped'; js = 'skipped'; deps = 'on';
    osv = 'skipped'; git_history = 'skipped'; manifest = 'on';
    external_aguara = 'skipped'; external_skill_scanner = 'skipped'
  }

  $item = Get-Item -Force -LiteralPath $scanPath -ErrorAction Stop
  $isContainer = $item.PSIsContainer
  if ($item.PSIsContainer) {
    $allFiles = @(Get-ItemsSafe $root -errors $errors | Where-Object { $_.FullName -notmatch '\\\.git\\' })
  } else {
    $allFiles = @($item)
    $root = Split-Path $item.FullName -Parent
  }
  $result.root = $root

  # 目录枚举失败（无权限等）按 permission_denied 记录到跳过清单
  $permErrs = @($errors | Where-Object { $_.PSObject.Properties['reason'] -and $_.reason -eq 'permission_denied' })
  foreach ($de in $permErrs) {
    [void]$skipped.Add([pscustomobject]@{ file = $de.path; reason = 'permission_denied'; desc = '目录不可读（权限）' })
    $skipReasons[$de.path] = 'permission_denied'
    $fileStatus[$de.path] = 'partial'
  }
  foreach ($de in $permErrs) { [void]$errors.Remove($de) }

  # 统一规则集：注册表加载后 linePatterns/multiPatterns/hintPatterns 已生成（普通+简报共用）
  if ($briefMode -and -not $registryLoaded) { [void](Get-RegistryRules) }
  if ($briefMode -and -not $registryLoaded) { [void]$errors.Add('规则注册表不可用，简报模式退化为内置规则扫描') }
  $obfLen = 2000
  if ($briefMode -and $registry.config -and $registry.config.obfuscation_line_length) {
    try { $obfLen = [int]$registry.config.obfuscation_line_length } catch {}
  }

  # 分类：可扫描文本 vs 跳过清单
  $scanFiles = New-Object System.Collections.ArrayList
  foreach ($f in $allFiles) {
    if ($f.Name -like '.skillspector-baseline*' -or $f.Name -in @('.DS_Store', 'Thumbs.db')) { continue }
    if ($f.FullName -match '\\\.git\\') { continue }
    $ext = $f.Extension.ToLower()
    if ($assetExt -contains $ext) {
      [void]$skipped.Add([pscustomobject]@{ file = $f.FullName; reason = 'binary_asset'; desc = '已知静态资产（图片/字体/媒体）' })
      $skipReasons[$f.FullName] = 'binary_asset'
      $fileStatus[$f.FullName] = 'skipped'
      continue
    }
    if ($binaryExt -contains $ext) {
      [void]$skipped.Add([pscustomobject]@{ file = $f.FullName; reason = 'binary'; desc = '二进制文件（无法文本分析）' })
      $skipReasons[$f.FullName] = 'binary'
      $fileStatus[$f.FullName] = 'partial'
      continue
    }
    if ($f.Length -gt $MaxFileBytes) {
      [void]$skipped.Add([pscustomobject]@{ file = $f.FullName; reason = 'oversized'; desc = ('超过单文件分析上限 ' + [Math]::Round($MaxFileBytes / 1MB, 1) + 'MB') })
      $skipReasons[$f.FullName] = 'oversized'
      $fileStatus[$f.FullName] = 'partial'
      continue
    }
    if ($ext -notin $knownTextExt -and (Test-BinaryContent $f.FullName)) {
      [void]$skipped.Add([pscustomobject]@{ file = $f.FullName; reason = 'binary'; desc = '二进制内容（无法文本分析）' })
      $skipReasons[$f.FullName] = 'binary'
      $fileStatus[$f.FullName] = 'partial'
      continue
    }
    [void]$scanFiles.Add($f)
  }

  # 简报模式：注释词法分析（code 文件）
  $commentMap = @{}
  if ($briefMode) {
    $engines['lexer'] = 'skipped'
    $lexExts = @('.py','.pyw','.js','.mjs','.cjs','.ts','.tsx','.jsx','.ps1','.psm1','.psd1','.sh','.bash','.zsh','.rb','.pl','.lua','.html','.htm','.xml','.svg')
    $lexFiles = @($scanFiles | Where-Object { $_.Extension.ToLower() -in $lexExts } | Select-Object -ExpandProperty FullName)
    if ($lexFiles.Count -gt 0) {
      $py = Get-PythonExe
      if ($py) {
        $engines['lexer'] = 'running'
        $lexRaw = @(& $py -X utf8 $lexerScript @lexFiles 2>$null) -join ''
        if ($lexRaw) {
          try {
            $lexObj = $lexRaw | ConvertFrom-Json
            foreach ($prop in $lexObj.files.PSObject.Properties) { $commentMap[$prop.Name] = $prop.Value }
            $engines['lexer'] = 'on'
          } catch {
            $engines['lexer'] = 'degraded'
            [void]$errors.Add('注释词法分析输出解析失败: ' + $_.Exception.Message)
          }
        }
      } else {
        [void]$errors.Add('未找到 Python，注释语境识别已跳过')
      }
    }
  }

  # 逐文件单遍扫描
  foreach ($f in $scanFiles) {
    $content = Read-TextFile $f.FullName
    if ($null -eq $content) {
      $fileStatus[$f.FullName] = 'complete'
      continue
    }
    if ($content.Status -ne 'ok') {
      $skipReasons[$f.FullName] = $content.Status
      $sd = if ($content.Status -eq 'unsupported_encoding') { '编码无法识别（所有回退失败）' } else { '文件不可读（权限/占用）' }
      [void]$skipped.Add([pscustomobject]@{ file = $f.FullName; reason = $content.Status; desc = $sd })
      $fileStatus[$f.FullName] = 'partial'
      continue
    }
    $fileStatus[$f.FullName] = 'complete'
    $context = Get-ContextForFile $f $root
    if ($context -eq 'code') { $hasExec = $true }
    $isDoc = ($context -eq 'doc') -or $self
    $fenceSet = @{}
    $lines = $content.Text -split "`n"
    if ($context -eq 'doc') { $fenceSet = Get-FenceLines $lines }
    $commentLines = @{}
    if ($briefMode -and $commentMap.ContainsKey($f.FullName)) {
      foreach ($n in @($commentMap[$f.FullName].comment_lines)) { $commentLines[[int]$n] = $true }
    }
    $rules = if ($briefMode) { @($linePatterns) + @($hintPatterns) } else { $linePatterns }
    for ($li = 0; $li -lt $lines.Count; $li++) {
      $line = $lines[$li]
      $ln = $li + 1
      $lineHasObf = $false
      foreach ($p in $rules) {
        if ($f.Name -like '.env*' -and $p.id -in @('E2', 'CRED', 'SECRET_ENV_READ', 'CREDENTIAL_REQUEST')) { continue }
        foreach ($m in [regex]::Matches($line, $p.re, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
          if ($p.id -eq 'OBFUSCATION') { $lineHasObf = $true }
          $col = $m.Index + 1
          $inFence = $fenceSet.ContainsKey($ln)
          $inComment = $commentLines.ContainsKey($ln)
          $fctx = $context
          if ($inComment -and $context -eq 'code') { $fctx = 'comment' }
          elseif ($context -eq 'doc' -and $inFence) { $fctx = 'doc_code' }
          $doc = $isDoc -or $inFence -or $inComment
          if (-not $briefMode) {
            if ($doc -and $f.Name -eq 'SKILL.md' -and $p.id -in $instructionIds -and -not $inFence) {
              $doc = $self
            }
          } else {
            if ($self) { $doc = $true }
            elseif ($fctx -eq 'doc_code') { $doc = $false }
            elseif ($fctx -in @('comment', 'doc')) { $doc = $true }
            if ($f.Name -eq 'SKILL.md' -and $p.id -in $instructionIds -and -not $inFence -and -not $inComment) { $doc = $self }
          }
          $text = $line.Trim()
          if ($text.Length -gt 160) { $text = $text.Substring(0, 160) + '…' }
          $score = if ($p.PSObject.Properties['score']) { [bool]$p.score } else { $true }
          $act = Get-Activity $m.Value
          $inv = Get-Invocation $m.Value
          $exec = if ($fctx -eq 'doc_code') { 'documented' } elseif ($context -eq 'code') { 'executable' } else { 'unknown' }
          $conf = Get-Confidence -activity $act -invocation $inv -execution $exec -context $fctx -fileStatus $fileStatus[$f.FullName]
          $evRefs = @()
          if ($p.id -in @('SSRF', 'CRED', 'SC2', 'DC')) {
            $inspKey = 'regex|' + $p.id
            if (-not $inspectionCache.ContainsKey($inspKey)) {
              $inspectionCache[$inspKey] = (Get-Sha256Hex (ConvertTo-CanonicalJson ([ordered]@{ target = $targetId; engine = 'regex'; rule = $p.id; scanner = $scannerVersion }))).Substring(0, 24)
            }
            $ev = New-Evidence -targetId $targetId -inspectionId $inspectionCache[$inspKey] -ruleId $p.id -file $f.FullName -lineStart $ln -evidenceType 'pattern' -extractor 'regex' -observed $text -strength 'E1' -origin 'native' -engine 'regex' -sourceType $sourceType
            if (-not $evidenceSeen.ContainsKey($ev.evidence_id)) {
              $evidenceSeen[$ev.evidence_id] = $true
              [void]$evidencePool.Add($ev)
            }
            $evRefs = @($ev.evidence_id)
          }
          [void]$findings.Add((New-Finding -id $p.id -severity $p.sev -file $f.FullName -line $ln -column $col -text $text -context $fctx -doc $doc -score $score -activity $act -invocation $inv -execution $exec -confidence $conf -evidenceRefs $evRefs -analyzer 'regex'))
        }
      }
      # OBFUSCATION 补充启发式：非注释/非文档超长单行（简报模式，阈值可配置）
      if ($briefMode -and -not $lineHasObf -and $line.Length -gt $obfLen -and -not $commentLines.ContainsKey($ln)) {
        $fctx2 = if ($context -eq 'doc' -and $fenceSet.ContainsKey($ln)) { 'doc_code' } else { $context }
        # 语境边界：只在真实代码文件（code）或文档内代码块（doc_code）触发；config/doc 正文不触发
        if ($context -eq 'code' -or $fctx2 -eq 'doc_code') {
          $doc2 = $false
          if ($self) { $doc2 = $true }
          elseif ($fctx2 -eq 'doc_code') { $doc2 = $false }
          elseif ($fctx2 -in @('comment', 'doc')) { $doc2 = $true }
          $exec2 = if ($fctx2 -eq 'doc_code') { 'documented' } elseif ($context -eq 'code') { 'executable' } else { 'unknown' }
          $conf2 = if ($fctx2 -eq 'doc_code') { 'low' } else { 'medium' }
          $snip = $line
          if ($snip.Length -gt 120) { $snip = $snip.Substring(0, 120) + '…' }
          [void]$findings.Add((New-Finding -id 'OBFUSCATION' -severity 'suspicious' -file $f.FullName -line $ln -column 1 -text ($snip + '（超长单行 ' + $line.Length + ' 字符）') -context $fctx2 -doc $doc2 -score $true -activity 'unknown' -invocation 'unknown' -execution $exec2 -confidence $conf2 -analyzer 'obfuscation'))
        }
      }
      # 网络地址分类（简报模式）：IPv4/IPv6 统一走分类器生成 LOOPBACK/INTERNAL/PUBLIC finding
      if ($briefMode -and -not $commentLines.ContainsKey($ln)) {
        foreach ($ip in @(Get-IpCandidates $line)) {
          if ($ip -eq '169.254.169.254') { continue }
          $cls = Get-AddressClass $ip
          $netId = $null; $netSev = ''; $netScore = $false
          if ($cls -eq 'loopback') { $netId = 'LOOPBACK_ACCESS'; $netSev = 'reference'; $netScore = $false }
          elseif ($cls -in @('private', 'link-local')) { $netId = 'INTERNAL_NET_CALL'; $netSev = 'suspicious'; $netScore = $true }
          elseif ($cls -eq 'public') { $netId = 'PUBLIC_IP_CALL'; $netSev = 'critical'; $netScore = $true }
          if (-not $netId) { continue }
          $fctx3 = if ($context -eq 'doc' -and $fenceSet.ContainsKey($ln)) { 'doc_code' } else { $context }
          $doc3 = $false
          if ($self) { $doc3 = $true }
          elseif ($fctx3 -eq 'doc_code') { $doc3 = $false }
          elseif ($fctx3 -in @('comment', 'doc')) { $doc3 = $true }
          $exec3 = if ($fctx3 -eq 'doc_code') { 'documented' } elseif ($context -eq 'code') { 'executable' } else { 'unknown' }
          $conf3 = if ($fctx3 -eq 'doc_code') { 'low' } else { 'medium' }
          $col3 = $line.IndexOf($ip) + 1
          if ($col3 -le 0) { $col3 = 1 }
          $inspKey3 = 'address_classifier|' + $netId
          if (-not $inspectionCache.ContainsKey($inspKey3)) {
            $inspectionCache[$inspKey3] = (Get-Sha256Hex (ConvertTo-CanonicalJson ([ordered]@{ target = $targetId; engine = 'address_classifier'; rule = $netId; scanner = $scannerVersion }))).Substring(0, 24)
          }
          $ev3 = New-Evidence -targetId $targetId -inspectionId $inspectionCache[$inspKey3] -ruleId $netId -file $f.FullName -lineStart $ln -evidenceType 'address_classification' -extractor 'address_classifier' -observed ('网络地址(' + $cls + '): ' + $ip) -strength 'E2' -origin 'native' -engine 'address_classifier' -sourceType $sourceType
          if (-not $evidenceSeen.ContainsKey($ev3.evidence_id)) {
            $evidenceSeen[$ev3.evidence_id] = $true
            [void]$evidencePool.Add($ev3)
          }
          [void]$findings.Add((New-Finding -id $netId -severity $netSev -file $f.FullName -line $ln -column $col3 -text ('网络地址(' + $cls + '): ' + $ip) -context $fctx3 -doc $doc3 -score $netScore -activity 'active' -invocation 'unknown' -execution $exec3 -confidence $conf3 -evidenceRefs @($ev3.evidence_id) -analyzer 'address_classifier'))
        }
      }
    }
    foreach ($p in $multiPatterns) {
      foreach ($m in [regex]::Matches($content.Text, $p.re, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
        $ln = Get-LineNumber $content.Text $m.Index
        $t = $m.Value -replace '\s+', ' '
        if ($t.Length -gt 160) { $t = $t.Substring(0, 160) + '…' }
        $docM = $isDoc -or $fenceSet.ContainsKey($ln)
        $execM = if ($docM) { 'documented' } else { 'executable' }
        [void]$findings.Add((New-Finding -id $p.id -severity $p.sev -file $f.FullName -line $ln -text ('多行特征: ' + $t) -context $context -doc $docM -execution $execM -analyzer 'multi'))
      }
    }
    foreach ($bf in @(Test-Base64Payload -text $content.Text -file $f.FullName -context $context -doc $isDoc)) {
      [void]$findings.Add($bf)
    }
  }

  # 专项检查
  foreach ($ef in @(Get-EnvCredentialFindings $root)) { [void]$findings.Add($ef) }
  foreach ($mf in @(Get-MetaFindings $root)) { [void]$findings.Add($mf) }
  foreach ($lf in @(Get-LinkFindings $root)) { [void]$findings.Add($lf) }
  $depResult = Get-DependencyAnalysis $root
  foreach ($df in @($depResult.Findings)) { [void]$findings.Add($df) }
  $result.dependencies = @($depResult.Findings)
  foreach ($c in @($depResult.Cve)) { [void]$cveCandidates.Add($c) }

  # Python AST（发现 .py 文件且 Python 可用时自动执行）
  $codeFiles = @($scanFiles | Where-Object { $_.Extension.ToLower() -in @('.py', '.js', '.mjs', '.cjs') } | Select-Object -ExpandProperty FullName)
  if (-not $NoAst -and $codeFiles.Count -gt 0) {
    $engines['python_ast'] = 'running'
    $astRes = Invoke-AstCheck -pyFiles $codeFiles -errors $errors -targetId $targetId -sourceType $sourceType
    foreach ($af in @($astRes.Findings)) { [void]$findings.Add($af) }
    foreach ($aev in @($astRes.Evidence)) {
      if (-not $evidenceSeen.ContainsKey($aev.evidence_id)) {
        $evidenceSeen[$aev.evidence_id] = $true
        [void]$evidencePool.Add($aev)
      }
    }
    foreach ($sf in @($astRes.SkippedFiles)) { $fileStatus[$sf] = 'partial' }
    $engines['python_ast'] = if (@($astRes.SkippedFiles).Count -gt 0) { 'degraded' } else { 'on' }
  } else {
    $engines['python_ast'] = if ($NoAst) { 'disabled' } else { 'skipped' }
  }
  $engines['js'] = if ($NoAst -or -not (Get-PythonExe)) { 'skipped' }
    elseif (@($codeFiles | Where-Object { $_ -match '(?i)\.(js|mjs|cjs)$' }).Count -eq 0) { 'skipped' }
    else { 'on' }

  # OSV 已知漏洞查询
  $osvErrBefore = @($errors).Count
  foreach ($of in @(Invoke-OsvCheck -cveCandidates $cveCandidates -errors $errors)) { [void]$findings.Add($of) }
  $engines['osv'] = if (-not $CheckCVE) { 'skipped' } elseif ($cveCandidates.Count -eq 0) { 'skipped' }
    elseif (@($errors).Count -gt $osvErrBefore) { 'degraded' } else { 'on' }

  # manifest 变化检测（需基线）
  foreach ($mf2 in @(Get-ManifestChangeFindings $root)) { [void]$findings.Add($mf2) }

  # git 历史敏感信息（可选）
  $gitErrBefore = @($errors).Count
  foreach ($gf in @(Get-GitHistoryFindings $root $errors)) { [void]$findings.Add($gf) }
  $engines['git_history'] = if (-not $GitHistory) { 'skipped' } elseif (-not (Get-GitExe)) { 'skipped' }
    elseif (@($errors).Count -gt $gitErrBefore) { 'degraded' } else { 'on' }

  # 可选外部扫描器适配层（仅目录目标；aguara / skill-scanner 自动探测，缺失 SKIP）
  if ($isContainer) {
    foreach ($ef in @(Invoke-ExternalScanners -root $root -errors $errors -engines $engines)) { [void]$findings.Add($ef) }
  } else {
    $engines['external_aguara'] = 'skipped'
    $engines['external_skill_scanner'] = 'skipped'
  }

  # 去重（id + 文件 + 行）：同键保留“非 doc 优先，其次高置信”
  $seen = @{}
  $unique = New-Object System.Collections.ArrayList
  foreach ($f in $findings) {
    $key = $f.id + '|' + $f.file + '|' + $f.line
    if (-not $seen.ContainsKey($key)) {
      $seen[$key] = $f
      [void]$unique.Add($f)
      continue
    }
    $ex = $seen[$key]
    $confRank = @{ high = 3; medium = 2; low = 1 }
    $exP = 0; if ($confRank.ContainsKey($ex.confidence)) { $exP = $confRank[$ex.confidence] }
    $fP = 0; if ($confRank.ContainsKey($f.confidence)) { $fP = $confRank[$f.confidence] }
    $better = $false
    if ((-not $f.doc) -and $ex.doc) { $better = $true }
    elseif ($f.doc -eq $ex.doc -and $fP -gt $exP) { $better = $true }
    if ($better) {
      $idx = $unique.IndexOf($ex)
      $unique[$idx] = $f
      $seen[$key] = $f
    }
  }
  $findings = $unique

  # Evidence 正式化：为无原生 evidence 的 finding 生成派生 evidence（extractor=derive, E1）；
  # 已原生接入的 analyzer（regex 高危规则 / 地址分类 / AST）保持原生 Evidence
  foreach ($f in $findings) {
    if (@($f.evidence_refs).Count -eq 0) {
      $analyzerOf = $(if ($f.analyzer) { $f.analyzer } else { 'unknown' })
      $inspKey = 'derive|' + $analyzerOf + '|' + $f.id
      if (-not $inspectionCache.ContainsKey($inspKey)) {
        $inspectionCache[$inspKey] = (Get-Sha256Hex (ConvertTo-CanonicalJson ([ordered]@{ target = $targetId; engine = $analyzerOf; rule = $f.id; scanner = $scannerVersion }))).Substring(0, 24)
      }
      $ev = New-Evidence -targetId $targetId -inspectionId $inspectionCache[$inspKey] -ruleId $f.id -file $f.file -lineStart ([int]$f.line) -evidenceType 'derived' -extractor 'derive' -observed ([string]$f.text) -strength 'E1' -origin 'derived' -engine $analyzerOf -sourceType $sourceType
      if (-not $evidenceSeen.ContainsKey($ev.evidence_id)) {
        $evidenceSeen[$ev.evidence_id] = $true
        [void]$evidencePool.Add($ev)
      }
      $f | Add-Member -NotePropertyName evidence_refs -NotePropertyValue @($ev.evidence_id) -Force
    }
  }
  # 简报模式：关联规则（受限共存）
  if ($briefMode) {
    foreach ($cf in @(Get-CorrelationFindings $findings)) { [void]$findings.Add($cf) }
    # correlation 原生 evidence：parent_evidence_ids = 源 finding evidence_refs 并集
    foreach ($cf in @($findings | Where-Object { $_.analyzer -eq 'correlation' })) {
      $parentIds = New-Object System.Collections.ArrayList
      foreach ($sid in @($cf.source_finding_id)) {
        $src = @($findings | Where-Object { $_.finding_id -eq $sid })[0]
        if ($src) {
          foreach ($r in @($src.evidence_refs)) { if ($parentIds -notcontains $r) { [void]$parentIds.Add($r) } }
        }
      }
      $inspKey = 'correlation|' + $cf.id
      if (-not $inspectionCache.ContainsKey($inspKey)) {
        $inspectionCache[$inspKey] = (Get-Sha256Hex (ConvertTo-CanonicalJson ([ordered]@{ target = $targetId; engine = 'correlation'; rule = $cf.id; scanner = $scannerVersion }))).Substring(0, 24)
      }
      $ev = New-Evidence -targetId $targetId -inspectionId $inspectionCache[$inspKey] -ruleId $cf.id -file $cf.file -lineStart ([int]$cf.line) -evidenceType 'correlation' -extractor 'correlation' -observed ([string]$cf.text) -strength 'E2' -origin 'native' -engine 'correlation' -sourceType $sourceType -parentEvidenceIds @($parentIds)
      if (-not $evidenceSeen.ContainsKey($ev.evidence_id)) {
        $evidenceSeen[$ev.evidence_id] = $true
        [void]$evidencePool.Add($ev)
      }
      $cf | Add-Member -NotePropertyName evidence_refs -NotePropertyValue @($ev.evidence_id) -Force
    }
  }
  $result.evidence = @($evidencePool)
  $result.target_id = $targetId

  # baseline 抑制
  foreach ($f in $findings) {
    if ($baselineFp.Count -gt 0) {
      $rel = $f.file.Substring($root.Length).TrimStart('\', '/')
      $fp = Get-Fingerprint $f.id $rel $f.line $f.text
      if ($baselineFp.ContainsKey($fp)) { $f | Add-Member -NotePropertyName suppressed -NotePropertyValue $true -Force }
    }
    if ($f.PSObject.Properties['suppressed'] -and $f.suppressed) {
      [void]$suppressed.Add($f)
    }
  }

  # 评分：排除文档语境与基线抑制；同一文件同类合并计分
  # 自扫豁免：专项检查器（依赖/meta/AST 等）不感知 $self，统一把自身命中标为文档语境（不计分）
  if ($self) {
    foreach ($f in $findings) {
      if ($f.PSObject.Properties['doc']) { $f.doc = $true }
    }
  }
  $score = 0
  $scoreKeys = @{}
  $effective = @($findings | Where-Object { -not $_.doc -and -not ($_.PSObject.Properties['suppressed'] -and $_.suppressed) })
  foreach ($f in $effective) {
    if (-not $f.score) { continue }
    $k = $f.id + '|' + $f.file
    if ($scoreKeys.ContainsKey($k)) { continue }
    $scoreKeys[$k] = $true
    $score += $sevPoints[$f.severity]
  }
  if ($hasExec) { $score = [Math]::Round($score * 1.3) }
  if ($score -gt 100) { $score = 100 }
  if ($score -le 20) { $sev = 'LOW'; $rec = 'SAFE 可安装' }
  elseif ($score -le 50) { $sev = 'MEDIUM'; $rec = 'CAUTION 谨慎' }
  elseif ($score -le 80) { $sev = 'HIGH'; $rec = 'DO NOT INSTALL 不建议' }
  else { $sev = 'CRITICAL'; $rec = 'DO NOT INSTALL 禁止' }

  # 概览统计：严重分布、重点类别、关键发现（供人读报告使用）
  $sevCount = @{ CRITICAL = 0; HIGH = 0; MED = 0; LOW = 0 }
  $catCount = @{}
  foreach ($f in $effective) {
    $sevCount[$f.severity]++
    if ($catCount.ContainsKey($f.id)) { $catCount[$f.id]++ } else { $catCount[$f.id] = 1 }
  }
  $topCats = @($catCount.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 5 | ForEach-Object {
    $d = if ($descMap.ContainsKey($_.Key)) { $descMap[$_.Key] } else { $_.Key }
    $_.Key + '(' + $d + ')×' + $_.Value
  })
  $topFindings = @($effective | Sort-Object -Property @{ Expression = { $sevPoints[$_.severity] }; Descending = $true }, file, line | Select-Object -First 5)
  $result.severityCounts = [pscustomobject]@{ CRITICAL = $sevCount['CRITICAL']; HIGH = $sevCount['HIGH']; MEDIUM = $sevCount['MED']; LOW = $sevCount['LOW'] }
  $result.topCategories = @($topCats)
  $result.topFindings = @($topFindings)

  $result.score = $score
  $result.severity = $sev
  $result.recommendation = $rec
  $result.hasExecutable = $hasExec
  if ($briefMode) {
    foreach ($fd in $findings) {
      if (-not ($fd.PSObject.Properties['brief_id'])) {
        $fd | Add-Member -NotePropertyName brief_id -NotePropertyValue (Get-BriefView $fd).brief_id -Force
      }
    }
  }
  $result.findings = @($findings)
  $result.suppressed = @($suppressed)
  $result.skipped = @($skipped)
  $result.errors = @($errors)
  $result.scan_files = @($scanFiles | Select-Object -ExpandProperty FullName)
  $result.skip_reasons = $skipReasons
  $result.analysis_status = if (@($fileStatus.Values | Where-Object { $_ -eq 'failed' }).Count -gt 0) { 'failed' } elseif (@($fileStatus.Values | Where-Object { $_ -eq 'partial' }).Count -gt 0) { 'partial' } else { 'complete' }
  $result.rules = [pscustomobject]@{ version = $registry.rules_version; schema = $registry.schema_version; scanner = $scannerVersion }
  $result.engines = [pscustomobject]@{
    regex = $engines['regex']; multi = $engines['multi']; lexer = $engines['lexer']
    python_ast = $engines['python_ast']; js = $engines['js']; deps = $engines['deps']
    osv = $engines['osv']; git_history = $engines['git_history']; manifest = $engines['manifest']
    external_aguara = $engines['external_aguara']; external_skill_scanner = $engines['external_skill_scanner']
  }
  if ($briefMode) {
    $result.reference_findings = @($findings | Where-Object { $_.doc })
    $result.correlation_findings = @($findings | Where-Object { $_.id -eq 'CREDENTIAL_LOOPBACK_COEXIST' })
    $result.dependency_findings = @($depResult.Brief)
    $result.behavior_summary = @(Get-BehaviorSummary $findings)
    $result.top3 = @(Get-BriefTop3 $findings)
    $result.verification = Get-VerificationStatus $root $result.scan_files
  }
  return $result
}

function Invoke-TargetScan {
  param([string]$target)
  $tempDir = $null
  $scanPath = $target
  if ($target -match '\.zip$' -and (Test-Path -LiteralPath $target -PathType Leaf)) {
    $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ('skillspector-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
    $errors = New-Object System.Collections.ArrayList
    try {
      Expand-SafeZip -zip $target -dest $tempDir -errors $errors
      if ($errors.Count -gt 0) {
        return [ordered]@{ path = $target; root = $target; target_type = 'file'; skill_name = ''; score = 0; severity = 'LOW'; recommendation = '扫描失败'; hasExecutable = $false; findings = @(); suppressed = @(); dependencies = @(); skipped = @(); errors = @($errors) }
      }
      $scanPath = $tempDir
    } catch {
      return [ordered]@{ path = $target; root = $target; target_type = 'file'; skill_name = ''; score = 0; severity = 'LOW'; recommendation = '扫描失败'; hasExecutable = $false; findings = @(); suppressed = @(); dependencies = @(); skipped = @(); errors = @($errors) }
    }
  }
  try {
    return (Invoke-ScanPath -scanPath $scanPath -displayPath $target)
  } finally {
    if ($tempDir -and (Test-Path -LiteralPath $tempDir)) {
      Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
}

function Get-Activity {
  # 固定启发式：命中片段含变量/参数/环境读取 → passive/mixed；字面量 → active
  param([string]$matchText)
  $varLike = $matchText -match '\$\w+|process\.env|os\.environ\s*\[|os\.getenv\s*\(|getenv\s*\(|environ\.get|\.get\s*\(|input\s*\(|\bargv\b|param\s*\('
  if ($varLike) {
    if ($matchText -match 'https?://|/[\w.\-]+/') { return 'mixed' }
    return 'passive'
  }
  return 'active'
}

function Get-Invocation {
  # 固定启发式：入口模式 → framework_entry；动态访问 → dynamic；函数定义行 → not_called；其余 unknown
  param([string]$matchText)
  if ($matchText -match '__main__|^\s*main\s*\(') { return 'framework_entry' }
  if ($matchText -match 'getattr\s*\(|globals\(\)\s*\[|locals\(\)\s*\[') { return 'dynamic' }
  if ($matchText -match '^\s*(async\s+def|def|function|func)\s+\w+\s*\(') { return 'not_called' }
  return 'unknown'
}

function Get-Confidence {
  # 固定算法：doc_code/解析失败 → low；executable + active + framework_entry → high；其余 medium
  param([string]$activity, [string]$invocation, [string]$execution, [string]$context, [string]$fileStatus)
  if ($context -eq 'doc_code' -or $fileStatus -in @('partial', 'failed')) { return 'low' }
  if ($execution -ne 'executable') { return 'low' }
  if ($activity -eq 'active' -and $invocation -eq 'framework_entry') { return 'high' }
  return 'medium'
}

function Get-CorrelationFindings {
  # 数据驱动关联：按注册表 correlation 规则的 when_all 条件匹配（只断言共存，不推断数据流）
  param($findings)
  $out = New-Object System.Collections.ArrayList
  foreach ($rule in @($registry.rules | Where-Object { $_.rule_type -eq 'correlation' })) {
    if (-not $rule.when_all -or @($rule.when_all).Count -eq 0) { continue }
    $conds = @($rule.when_all)
    $matchedBy = @{}
    $allOk = $true
    foreach ($cond in $conds) {
      $condOk = $false
      if ($cond -match '^category:(.+)$') {
        $cat = $matches[1]
        foreach ($f in $findings) {
          if ($f.doc) { continue }
          $v = Get-BriefView $f
          $fc = if ($v.projected) { $v.category } elseif ($ruleCategory.ContainsKey($f.id)) { $ruleCategory[$f.id] } else { '' }
          if ($fc -eq $cat) { $condOk = $true; $matchedBy[$f.finding_id] = $true }
        }
      } elseif ($cond -match '^id:(.+)$') {
        $rid = $matches[1]
        foreach ($f in $findings) {
          if ($f.id -eq $rid -or (Get-BriefView $f).brief_id -eq $rid) { $condOk = $true; $matchedBy[$f.finding_id] = $true }
        }
      }
      if (-not $condOk) { $allOk = $false; break }
    }
    if (-not $allOk) { continue }
    $srcFindings = @($findings | Where-Object { $matchedBy.ContainsKey($_.finding_id) })
    if ($srcFindings.Count -lt 2) { continue }
    $conf = 'high'
    foreach ($s in $srcFindings) { if ($s.confidence -ne 'high') { $conf = 'medium' } }
    $f0 = $srcFindings[0]
    $sources = New-Object System.Collections.ArrayList
    foreach ($s in $srcFindings) { [void]$sources.Add([ordered]@{ finding_id = $s.finding_id; file = $s.file; line = $s.line; snippet = $s.text }) }
  $f = New-Finding -id $rule.rule_id -severity $rule.severity -file $f0.file -line $f0.line -column $f0.column -text $rule.description -context 'code' -doc $false -score $false -activity 'unknown' -invocation 'unknown' -execution 'unknown' -confidence $conf -analyzer 'correlation'
    $f.source_finding_id = @($srcFindings | ForEach-Object { $_.finding_id })
    $f | Add-Member -NotePropertyName sources -NotePropertyValue @($sources) -Force
    [void]$out.Add($f)
  }
  return $out
}

function Get-BehaviorSummary {
  # 确定性聚合：命中规则 → category → 去重 → 最多 5 个
  param($findings)
  $cats = @($findings | Where-Object { -not $_.doc -and $_.id -ne 'CREDENTIAL_LOOPBACK_COEXIST' -and -not (Get-BriefView $_).hide } | ForEach-Object {
    $v = Get-BriefView $_
    if ($v.projected) { $v.category }
    elseif ($ruleCategory.ContainsKey($_.id)) { $ruleCategory[$_.id] }
    else { $null }
  } | Where-Object { $_ } | Select-Object -Unique)
  if ($cats.Count -gt 5) { $cats = @($cats[0..4]) }
  return @($cats)
}

function Get-BriefTop3 {
  # 固定排序：severity > confidence > activity > invocation > execution > rule_priority > file/column/line/finding_id
  param($findings)
  $sevRank = @{ critical = 2; suspicious = 1; info = 0; reference = 0 }
  $confRank = @{ high = 3; medium = 2; low = 1 }
  $actRank = @{ active = 4; mixed = 3; passive = 2; unknown = 1 }
  $invRank = @{ framework_entry = 4; dynamic = 3; unknown = 2; not_called = 1 }
  $execRank = @{ executable = 3; unknown = 2; documented = 1 }
  $cands = @($findings | Where-Object { -not $_.doc -and $_.id -ne 'CREDENTIAL_LOOPBACK_COEXIST' -and -not (Get-BriefView $_).hide })
  $sorted = @($cands | Sort-Object -Property `
    @{ Expression = { $sevRank[(Get-BriefSeverity (Get-BriefView $_).severity)] }; Descending = $true }, `
    @{ Expression = { $confRank[$_.confidence] }; Descending = $true }, `
    @{ Expression = { $actRank[$_.activity] }; Descending = $true }, `
    @{ Expression = { $invRank[$_.invocation] }; Descending = $true }, `
    @{ Expression = { $execRank[$_.execution] }; Descending = $true }, `
    @{ Expression = { $v = Get-BriefView $_; if ($v.projected) { $v.priority } elseif ($rulePriority.ContainsKey($_.id)) { $rulePriority[$_.id] } else { 0 } }; Descending = $true }, `
    file, column, line, finding_id)
  return @($sorted | Select-Object -First 3)
}

function Get-EditDistance {
  # Levenshtein 距离（小字符串用）
  param([string]$a, [string]$b)
  $la = $a.Length; $lb = $b.Length
  if ($la -eq 0) { return $lb }
  if ($lb -eq 0) { return $la }
  $prev = New-Object int[] ($lb + 1)
  $cur = New-Object int[] ($lb + 1)
  for ($j = 0; $j -le $lb; $j++) { $prev[$j] = $j }
  for ($i = 1; $i -le $la; $i++) {
    $cur[0] = $i
    for ($j = 1; $j -le $lb; $j++) {
      $cost = if ($a[$i - 1] -eq $b[$j - 1]) { 0 } else { 1 }
      $cur[$j] = [Math]::Min([Math]::Min(($prev[$j] + 1), ($cur[$j - 1] + 1)), ($prev[$j - 1] + $cost))
    }
    $tmp = $prev; $prev = $cur; $cur = $tmp
  }
  return $prev[$lb]
}

function Get-DependencyAnalysis {
  # 统一依赖分析：一次收集（declared/imported/源/钩子），投影为 SC1（普通）与 DEP_*（简报）
  param([string]$root)
  $sc1 = New-Object System.Collections.ArrayList
  $dep = New-Object System.Collections.ArrayList
  $cveCandidates = New-Object System.Collections.ArrayList
  $declared = @{}
  $imported = @{}
  $kp = @()
  $kpPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'data\known_packages.json'
  if (Test-Path -LiteralPath $kpPath) {
    try { $kp = @((Get-Content -Raw -Encoding UTF8 -LiteralPath $kpPath | ConvertFrom-Json).packages) } catch {}
  }
  $whitelist = @($registry.config.source_whitelist)
  $maxDeps = if ($registry.config.max_direct_deps) { [int]$registry.config.max_direct_deps } else { 30 }

  # requirements / Pipfile / environment.yml
  foreach ($rf in @(Get-ItemsSafe $root | Where-Object { $_.Name -match '^(requirements.*\.txt|Pipfile|environment\.ya?ml)$' })) {
    $lines = @(Get-Content -Encoding UTF8 -LiteralPath $rf.FullName -ErrorAction SilentlyContinue)
    for ($i = 0; $i -lt $lines.Count; $i++) {
      $l = $lines[$i].Trim()
      if ($l -eq '' -or $l.StartsWith('#') -or $l.StartsWith('[')) { continue }
      if ($l -match '^\s*--index-url\s+(\S+)' -or $l -match '^\s*-i\s+(\S+)') {
        $src = $matches[1]
        if (-not ($whitelist | Where-Object { $src.StartsWith($_, [System.StringComparison]::OrdinalIgnoreCase) })) {
[void]$dep.Add((New-Finding -id 'DEP_SOURCE' -severity 'suspicious' -file $rf.FullName -line ($i + 1) -text ('依赖源不在白名单: ' + $src) -context 'config' -doc $false -analyzer 'deps'))
        }
        continue
      }
      if ($l -match '^(git\+)?https?://(\S+)') {
        $src = $matches[1] + $matches[2]
        if ($l -notmatch '@[0-9a-fA-F]{7,}') {
[void]$sc1.Add((New-Finding -id 'SC1' -severity 'LOW' -file $rf.FullName -line ($i + 1) -text ('git 依赖未锁定提交: ' + $l) -context 'config' -doc $false -analyzer 'deps'))
        }
        $nonWhitelist = -not ($whitelist | Where-Object { $src.StartsWith($_, [System.StringComparison]::OrdinalIgnoreCase) })
        if ($l -match '[#&]egg=([A-Za-z0-9_.\-]+)' -and $nonWhitelist) {
          $pkg = $matches[1]
          $declared[$pkg.ToLower()] = $true
          $near = @($kp | Where-Object { $_.Length -ge 4 -and (Get-EditDistance $pkg.ToLower() $_.ToLower()) -le 2 })
          if ($near.Count -gt 0) {
[void]$dep.Add((New-Finding -id 'DEP_TYPOSQUAT' -severity 'critical' -file $rf.FullName -line ($i + 1) -text ('疑似拼写相似包: ' + $pkg + '（相似于 ' + $near[0] + '，来源非白名单）') -context 'config' -doc $false -analyzer 'deps'))
          } else {
[void]$dep.Add((New-Finding -id 'DEP_SOURCE' -severity 'suspicious' -file $rf.FullName -line ($i + 1) -text ('依赖来自非白名单源: ' + $pkg + ' ← ' + $src) -context 'config' -doc $false -analyzer 'deps'))
          }
        } elseif ($nonWhitelist) {
[void]$dep.Add((New-Finding -id 'DEP_SOURCE' -severity 'suspicious' -file $rf.FullName -line ($i + 1) -text ('依赖 URL 不在白名单: ' + $src) -context 'config' -doc $false -analyzer 'deps'))
        }
        continue
      }
      if ($l -match '^([A-Za-z0-9_.\-]+)\s*(==|>=|<=|~=|!=|===|<|>)\s*([^\s;#]+)') {
        $pkg = $matches[1]; $op = $matches[2]; $ver = $matches[3]
        $declared[$pkg.ToLower()] = $true
        if ($op -eq '==' -or $op -eq '===') {
          [void]$cveCandidates.Add([pscustomobject]@{ eco = 'PyPI'; name = $pkg; version = $ver; file = $rf.FullName; line = $i + 1 })
        } else {
[void]$sc1.Add((New-Finding -id 'SC1' -severity 'LOW' -file $rf.FullName -line ($i + 1) -text ("依赖未锁定版本: $pkg ($op$ver)") -context 'config' -doc $false -analyzer 'deps'))
        }
      } elseif ($l -match '^([A-Za-z0-9_.\-]+)\s*(#.*)?$') {
        $declared[$matches[1].ToLower()] = $true
[void]$sc1.Add((New-Finding -id 'SC1' -severity 'LOW' -file $rf.FullName -line ($i + 1) -text ('依赖未锁定版本（无版本号）: ' + $matches[1]) -context 'config' -doc $false -analyzer 'deps'))
      }
    }
  }

  # pyproject.toml（SC1 锁定检查）
  foreach ($f in @(Get-ItemsSafe $root | Where-Object { $_.Name -eq 'pyproject.toml' })) {
    $lines = @(Get-Content -Encoding UTF8 -LiteralPath $f.FullName -ErrorAction SilentlyContinue)
    $section = ''
    for ($i = 0; $i -lt $lines.Count; $i++) {
      $l = $lines[$i].Trim()
      if ($l -match '^\[(.+)\]$') { $section = $matches[1]; continue }
      if ($section -notmatch 'dependenc') { continue }
      $items = New-Object System.Collections.ArrayList
      if ($l -match '^[\x22\x27]?([A-Za-z0-9_.\-]+)[\x22\x27]?\s*(==|>=|<=|~=|!=|===|<|>)\s*[\x22\x27]?([^\s\x22\x27#,]+)') {
        [void]$items.Add(@($matches[1], $matches[2], $matches[3]))
      } elseif ($l -match '=') {
        foreach ($m in [regex]::Matches($l, '[\x22\x27]([A-Za-z0-9_.\-]+(?:==|>=|<=|~=|!=|===|<|>)[^\x22\x27]+)[\x22\x27]')) {
          $spec = $m.Groups[1].Value
          if ($spec -match '^([A-Za-z0-9_.\-]+)\s*(==|>=|<=|~=|!=|===|<|>)\s*([^\s]+)') {
            [void]$items.Add(@($matches[1], $matches[2], $matches[3]))
          }
        }
      }
      foreach ($it in $items) {
        $pkg = $it[0]; $op = $it[1]; $ver = $it[2]
        $declared[$pkg.ToLower()] = $true
        if ($op -eq '==' -or $op -eq '===') {
          [void]$cveCandidates.Add([pscustomobject]@{ eco = 'PyPI'; name = $pkg; version = $ver; file = $f.FullName; line = $i + 1 })
        } else {
[void]$sc1.Add((New-Finding -id 'SC1' -severity 'LOW' -file $f.FullName -line ($i + 1) -text ("依赖未锁定版本: $pkg ($op$ver)") -context 'config' -doc $false -analyzer 'deps'))
        }
      }
    }
  }

  # package.json：declared + SC1 + DEP_HOOK 分层
  foreach ($f in @(Get-ItemsSafe $root | Where-Object { $_.Name -eq 'package.json' })) {
    try {
      $obj = Get-Content -Raw -Encoding UTF8 -LiteralPath $f.FullName -ErrorAction Stop | ConvertFrom-Json
      $lines = @(Get-Content -Encoding UTF8 -LiteralPath $f.FullName -ErrorAction SilentlyContinue)
      foreach ($sec in @('dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies')) {
        if ($obj.$sec) {
          foreach ($prop in $obj.$sec.PSObject.Properties) {
            $declared[$prop.Name.ToLower()] = $true
            $spec = [string]$prop.Value
            $pinned = ($spec -match '^\d') -and ($spec -notmatch '^[~^<>=]')
            $ln = 1
            for ($i = 0; $i -lt $lines.Count; $i++) {
              if ($lines[$i] -match ('"' + [regex]::Escape($prop.Name) + '"\s*:')) { $ln = $i + 1; break }
            }
            if (-not $pinned) {
[void]$sc1.Add((New-Finding -id 'SC1' -severity 'LOW' -file $f.FullName -line $ln -text ("npm 依赖未锁定版本: $($prop.Name) ($spec)") -context 'config' -doc $false -analyzer 'deps'))
            } else {
              [void]$cveCandidates.Add([pscustomobject]@{ eco = 'npm'; name = $prop.Name; version = $spec.TrimStart('=', ' '); file = $f.FullName; line = $ln })
            }
          }
        }
      }
      $hookNames = @('preinstall', 'postinstall', 'prepare')
      foreach ($hn in $hookNames) {
        if ($obj.scripts -and (@($obj.scripts.PSObject.Properties.Name) -contains $hn)) {
          $ln = 1
          for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match ('"' + $hn + '"\s*:')) { $ln = $i + 1; break }
          }
          $hookVal = [string]$obj.scripts.$hn
          $danger = $hookVal -match '(?i)(\bcurl\b|\bwget\b|Invoke-WebRequest|Invoke-RestMethod|Invoke-Expression|\biex\b|\bpowershell\b|\bcmd\b|\beval\s*\(|\bexec\s*\(|/bin/(ba)?sh|download|FromBase64|base64\s*-d)'
          $safe = $hookVal -match '(?i)^\s*(node-gyp rebuild|npm run [A-Za-z0-9_\-]+|yarn [A-Za-z0-9_\-]+|pnpm [A-Za-z0-9_\-]+|node \S+\.(js|mjs|cjs)(\s|$)|tsc(\s|$)|webpack(\s|$)|vite(\s|$)|rollup(\s|$)|esbuild(\s|$)|make(\s|$)|cmake(\s|$)|python \S+\.py|gradle(\s|$)|mvn(\s|$)|ng build|nest build)\s*$'
          $sev = 'suspicious'; $conf = 'medium'
          if ($danger) { $sev = 'critical'; $conf = 'high' }
          elseif ($hookVal.Trim() -ne '' -and -not $safe) { $sev = 'critical'; $conf = 'medium' }
[void]$dep.Add((New-Finding -id 'DEP_HOOK' -severity $sev -file $f.FullName -line $ln -text ('安装脚本钩子: ' + $hn + ' = ' + $hookVal) -context 'config' -doc $false -confidence $conf -analyzer 'deps'))
        }
      }
    } catch {}
  }

  # setup.py（DEP_HOOK）
  foreach ($rf in @(Get-ItemsSafe $root | Where-Object { $_.Name -eq 'setup.py' })) {
    $sl = @(Get-Content -Encoding UTF8 -LiteralPath $rf.FullName -ErrorAction SilentlyContinue)
    for ($i = 0; $i -lt $sl.Count; $i++) {
      if ($sl[$i] -match 'os\.system|subprocess|Popen|shutil\.rmtree|exec\s*\(') {
[void]$dep.Add((New-Finding -id 'DEP_HOOK' -severity 'critical' -file $rf.FullName -line ($i + 1) -text ('setup.py 执行系统命令: ' + $sl[$i].Trim()) -context 'code' -doc $false -analyzer 'deps'))
      }
    }
  }

  # 代码 import 收集 → DEP_UNDECLARED
  foreach ($cf in @(Get-ItemsSafe $root | Where-Object { $_.Extension.ToLower() -in @('.py', '.js', '.mjs', '.cjs', '.ts', '.tsx') })) {
    $cl = @(Get-Content -Encoding UTF8 -LiteralPath $cf.FullName -ErrorAction SilentlyContinue)
    foreach ($l in $cl) {
      $t = $l.Trim()
      if ($t -match '^\s*(import|from)\s+([A-Za-z0-9_]+)') { $imported[$matches[2].ToLower()] = $true }
      elseif ($t -match '(require\s*\(\s*[\x22\x27]|from\s+[\x22\x27])([A-Za-z0-9_\-\./@]+)[\x22\x27]') { $imported[($matches[2] -split '/')[0].ToLower()] = $true }
    }
  }
  foreach ($k in @($imported.Keys)) {
    if (-not $declared.ContainsKey($k) -and $k -notmatch '^(os|sys|re|json|pathlib|typing|collections|itertools|functools|math|random|datetime|time|subprocess|shutil|tempfile|logging|urllib|requests|http|ssl|socket|base64|hashlib|hmac|uuid|asyncio|concurrent|threading|multiprocessing|argparse|configparser|csv|io|string|struct|textwrap|unittest|inspect|traceback|warnings|abc|enum|glob|fnmatch|platform|signal|sqlite3|xml|html|webbrowser|zlib|gzip|bz2|lzma|zipfile|tarfile|pickle|shelve|dbm|email|calendar|decimal|fractions|numbers|operator|statistics|bisect|array|weakref|copy|pprint|dataclasses|contextlib|types|__future__|ast|dis|tokenize|token|keyword|codecs|builtins|gc|importlib|runpy|sysconfig|locale|gettext|unicodedata|venv|ensurepip|linecache|marshal|imp|site|code)$' -and $k -notmatch '^(node:|react|react-dom|vue|next|express|typescript|@types/|@/)') {
[void]$dep.Add((New-Finding -id 'DEP_UNDECLARED' -severity 'suspicious' -file $root -line 0 -text ('代码引用了未声明的包: ' + $k) -context 'config' -doc $false -analyzer 'deps'))
    }
  }

  if ($declared.Count -gt $maxDeps) {
[void]$dep.Add((New-Finding -id 'DEP_COUNT' -severity 'suspicious' -file $root -line 0 -text ('直接依赖数 ' + $declared.Count + ' 超过阈值 ' + $maxDeps) -context 'config' -doc $false -analyzer 'deps'))
  }
  return [pscustomobject]@{ Findings = $sc1; Brief = $dep; Cve = $cveCandidates }
}

function Get-TargetIdentity {
  param([string]$root)
  $full = [System.IO.Path]::GetFullPath($root)
  $norm = $full.Replace('\', '/').TrimEnd('/').ToLower()
  $hash = Get-Sha256Hex $norm
  $name = Split-Path $full -Leaf
  $safe = $name -replace '[\\/:*?"<>| ]', '_'
  return [pscustomobject]@{ identity = ($safe + '@' + $hash.Substring(0, 12)); path_hash = $hash.Substring(0, 12); name = $safe }
}

function Get-LedgerReasonCode {
  # Ledger 旁路：从 engines/errors 派生 reason_code（冻结枚举见 contracts/reason-codes.md）
  param([string]$engine, [string]$status, [string]$errorText)
  if ($status -eq 'executed') { return $null }
  if ($status -eq 'disabled') { return 'disabled_by_config' }
  if ($errorText) {
    if ($errorText -match '未找到 Python|外部扫描器|external_missing') { return 'external_missing' }
    if ($errorText -match 'OSV|已知漏洞|漏洞查询') { return 'dependency_unresolved' }
    if ($errorText -match 'AST 跳过|解析失败|parse') { return 'parse_error' }
    if ($errorText -match '权限|denied') { return 'permission_denied' }
    if ($errorText -match '编码') { return 'unsupported_encoding' }
  }
  if ($engine -in @('external_aguara', 'external_skill_scanner')) { return 'external_missing' }
  if ($engine -in @('osv', 'git_history', 'python_ast', 'js', 'lexer', 'deps')) { return 'not_applicable' }
  return 'unknown'
}

function New-InspectionLedger {
  # 旁路审计层：从既有 targets（engines/errors）派生 inspection[]，不创建/修改 Finding/Evidence，不参与评分
  param([object[]]$targets, [string]$runTs, [string]$scannerV, [string]$rulesV, [string]$policyV)
  $ids = @()
  foreach ($t in $targets) {
    $tid = if ($null -ne $t.target_id -and [string]$t.target_id) { [string]$t.target_id } else { (Get-TargetIdentity $t.root).identity }
    $ids += $tid
  }
  $ids = @($ids | Sort-Object)
  $fp = Get-Sha256Hex ($ids -join "`n")
  $runId = Get-Sha256Hex ($fp + '|' + $scannerV + '|' + $rulesV + '|' + $policyV + '|' + $runTs)
  $entries = New-Object System.Collections.ArrayList
  foreach ($t in $targets) {
    $tid = if ($null -ne $t.target_id -and [string]$t.target_id) { [string]$t.target_id } else { (Get-TargetIdentity $t.root).identity }
    $eng = if ($null -ne $t.engines) { $t.engines } else { [pscustomobject]@{} }
    $errText = ''
    if ($null -ne $t.errors) { $errText = (@($t.errors) | ForEach-Object { [string]$_ }) -join ' ' }
    $engNames = @($eng.PSObject.Properties | ForEach-Object { $_.Name })
    foreach ($k in $engNames) {
      if ([string]::IsNullOrEmpty($k)) { continue }
      $val = [string]$eng.$k
      $status = switch ($val) {
        'on' { 'executed' }; 'running' { 'executed' }
        'skipped' { 'skipped' }; 'disabled' { 'disabled' }
        'degraded' { 'degraded' }; 'failed' { 'failed' }
        default { 'degraded' }
      }
      $rc = Get-LedgerReasonCode -engine $k -status $status -errorText $errText
      [void]$entries.Add([pscustomobject]@{
        entry_id = (Get-Sha256Hex ($runId + '|' + $tid + '|' + $k)).Substring(0, 24)
        run_id = $runId
        target_id = $tid
        engine = $k
        status = $status
        reason_code = $rc
        coverage = $null
        started_at = $null
        finished_at = $null
        error = $null
      })
    }
  }
  return [pscustomobject]@{ run_id = $runId; entries = @($entries) }
}

function Get-VerifiedDir {
  $root = Get-SkillsRoot
  if ($root) { return Join-Path $root '.verified' }
  return Join-Path $env:USERPROFILE '.codex\skills\.verified'
}

function Get-ManifestForSkill {
  param([string]$root)
  $files = @{}
  $symlinks = @{}
  $exclNames = @('.skillspector-baseline.yaml', '.skillspector-verified.yaml', '.DS_Store', 'Thumbs.db')
  foreach ($f in @(Get-ItemsSafe $root)) {
    $rel = $f.FullName.Substring($root.Length).TrimStart('\', '/').Replace('\', '/')
    if ($rel -match '(^|/)\.git(/|$)' -or $rel -in $exclNames -or $f.Name -like '.skillspector-baseline*') { continue }
    if ($f.PSIsContainer) { continue }
    if ($f.Extension.ToLower() -in $assetExt) { continue }
    $files[$rel] = (Get-HashOfFile $f.FullName)
  }
  foreach ($l in @(Get-ItemsSafe $root -IncludeDirs | Where-Object { $_.LinkType })) {
    $rel = $l.FullName.Substring($root.Length).TrimStart('\', '/').Replace('\', '/')
    $symlinks[$rel] = [string]$l.Target
  }
  return [pscustomobject]@{ files = $files; symlinks = $symlinks }
}

function Write-AtomicJson {
  param([string]$path, $obj)
  $dir = Split-Path $path -Parent
  $tmp = Join-Path $dir ('.' + (Split-Path $path -Leaf) + '.tmp')
  $json = $obj | ConvertTo-Json -Depth 8
  $fs = [System.IO.File]::Create($tmp)
  try {
    $bytes = ([System.Text.UTF8Encoding]::new($false)).GetBytes($json)
    $fs.Write($bytes, 0, $bytes.Length)
    $fs.Flush($true)
  } finally { $fs.Dispose() }
  Move-Item -LiteralPath $tmp -Destination $path -Force
}

function Get-VerificationStatus {
  param([string]$root)
  $ti = Get-TargetIdentity $root
  $vp = Join-Path (Get-VerifiedDir) ($ti.identity + '.json')
  if (-not (Test-Path -LiteralPath $vp)) {
    return [pscustomobject]@{ status = 'none'; decision = ''; date = '' }
  }
  try {
    $v = Get-Content -Raw -Encoding UTF8 -LiteralPath $vp | ConvertFrom-Json
    $man = Get-ManifestForSkill $root
    $hashes = Get-RegistryHashes
    $curFiles = Get-Sha256Hex (ConvertTo-CanonicalJson $man.files)
    $oldFiles = Get-Sha256Hex (ConvertTo-CanonicalJson $v.files)
    $sameFiles = ($curFiles -eq $oldFiles)
    $sameEnv = ($v.scanner_version -eq $scannerVersion) -and ($v.rules_hash -eq $hashes.rules_hash) -and ($v.config_hash -eq $hashes.config_hash) -and ($v.known_packages_hash -eq $hashes.known_packages_hash) -and ($v.schema_version -eq $registry.schema_version) -and ($v.schema_hash -eq $hashes.schema_hash)
    if ($sameFiles -and $sameEnv) { return [pscustomobject]@{ status = 'valid'; decision = $v.decision; date = $v.verified_at } }
    if ($sameFiles -and -not $sameEnv) { return [pscustomobject]@{ status = 'stale_env'; decision = $v.decision; date = $v.verified_at } }
    return [pscustomobject]@{ status = 'stale_content'; decision = $v.decision; date = $v.verified_at }
  } catch {
    return [pscustomobject]@{ status = 'none'; decision = ''; date = '' }
  }
}

function Invoke-MarkVerified {
  param([string]$decision)
  $target = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
  $r = Invoke-TargetScan $target
  if ($r.analysis_status -ne 'complete') {
    throw ('analysis_status=' + $r.analysis_status + '，禁止写入已审记录（仅 complete 可审核）')
  }
  $man = Get-ManifestForSkill $r.root
  $hashes = Get-RegistryHashes
  $ti = Get-TargetIdentity $r.root
  $fpInput = [ordered]@{
    target_identity = $ti.identity
    files = $man.files
    symlinks = $man.symlinks
    scanner_version = $scannerVersion
    rules_version = $registry.rules_version
    rules_hash = $hashes.rules_hash
    config_version = '1.0.0'
    config_hash = $hashes.config_hash
    known_packages_version = $hashes.known_packages_version
    known_packages_hash = $hashes.known_packages_hash
    schema_version = $registry.schema_version
    schema_hash = $hashes.schema_hash
  }
  $record = [ordered]@{
    decision = $decision
    verified_at = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    scanner_version = $scannerVersion
    rules_version = $registry.rules_version
    rules_hash = $hashes.rules_hash
    config_version = '1.0.0'
    config_hash = $hashes.config_hash
    known_packages_version = $hashes.known_packages_version
    known_packages_hash = $hashes.known_packages_hash
    schema_version = $registry.schema_version
    schema_hash = $hashes.schema_hash
    report_fingerprint = (Get-Sha256Hex (ConvertTo-CanonicalJson $fpInput))
    target_identity = $ti.identity
    analysis_status = 'complete'
    files = $man.files
    symlinks = $man.symlinks
  }
  $dir = Get-VerifiedDir
  if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
  $vp = Join-Path $dir ($ti.identity + '.json')
  Write-AtomicJson $vp $record
  Write-Output ('已审记录已写入: ' + $vp + '（decision=' + $decision + '）')
}

function Get-VerificationText {
  param($v)
  if (-not $v) { return '无已审记录' }
  switch ($v.status) {
    'valid' { return ('上次已审：' + $v.decision + '（' + $v.date + '）') }
    'stale_env' { return ('扫描规则或配置已更新，上次结论可能失效（' + $v.date + '：' + $v.decision + '）') }
    'stale_content' { return ('内容已变，上次结论可能失效（' + $v.date + '：' + $v.decision + '）') }
    default { return '无已审记录' }
  }
}

function Invoke-PrePublishCheck {
  # 发布前门禁：黑名单文件 + 内容疑似密钥 + git 历史疑似密钥；只提醒不拦截。
  # git 不可用/非 git 仓库时历史检查显式 SKIP（不静默跳过），文件清单按目录内全部文件兜底。
  param([string]$target)
  if (-not (Test-Path -LiteralPath $target -PathType Container)) { throw '目标必须是目录' }
  $lines = New-Object System.Collections.ArrayList
  [void]$lines.Add('==== Pre-Publish 检查: ' + $target + ' ====')
  $failCount = 0
  $skipCount = 0

  # 1) 文件清单：git 仓库 = 已跟踪 + 未跟踪（非忽略）且位于目标目录下；非 git = 目录内全部文件（排除 .git 内部）
  $git = Get-GitExe
  $repoRoot = $null
  $prefix = $null
  $candidateFiles = New-Object System.Collections.ArrayList
  if ($git) {
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $repoRoot = (& $git -C $target rev-parse --show-toplevel 2>$null | Select-Object -First 1)
    $ErrorActionPreference = $prevEap
  }
  if ($repoRoot) {
    $prefix = (Resolve-Path -LiteralPath $repoRoot).Path.TrimEnd('\') + '\'
    $tracked = @(& $git -C $repoRoot ls-files 2>$null)
    $untracked = @(& $git -C $repoRoot ls-files --others --exclude-standard 2>$null)
    foreach ($rel in @($tracked + $untracked | Sort-Object -Unique)) {
      $full = Join-Path $repoRoot ($rel -replace '/', '\')
      if ($full.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $full)) {
        [void]$candidateFiles.Add($full)
      }
    }
  } else {
    foreach ($fi in @(Get-ChildItem -Recurse -File -LiteralPath $target -ErrorAction SilentlyContinue)) {
      if ($fi.FullName -notmatch '\\\.git\\') { [void]$candidateFiles.Add($fi.FullName) }
    }
  }
  $checkedFiles = @($candidateFiles).Count

  # 2) 黑名单文件（按相对路径/文件名匹配）
  $blocked = New-Object System.Collections.ArrayList
  foreach ($full in @($candidateFiles)) {
    $rel = if ($repoRoot) { $full.Substring($prefix.Length) } else { $full.Substring($target.Length).TrimStart('\') }
    $leaf = Split-Path $rel -Leaf
    $isBlocked = $false
    if ($rel -match '(^|[\\/])\.verified[\\/]') { $isBlocked = $true }
    elseif ($leaf -match '^\.env($|\.)|\.pem$|\.key$|^id_rsa|^id_ed25519|\.pfx$|\.p12$|^credentials|\.secret$') { $isBlocked = $true }
    if ($isBlocked) { [void]$blocked.Add($rel) }
  }
  if (@($blocked).Count -eq 0) {
    [void]$lines.Add(('[PASS] 文件清单: 无黑名单文件（检查 ' + $checkedFiles + ' 个将发布文件）'))
  } else {
    $failCount += @($blocked).Count
    foreach ($b in @($blocked | Sort-Object -Unique)) {
      [void]$lines.Add(('[FAIL] 文件清单: 黑名单文件将被发布: ' + $b))
    }
  }

  # 3) 内容疑似密钥：复用完整扫描引擎，只取 CRED 命中
  $r = Invoke-TargetScan $target
  if ($r.recommendation -eq '扫描失败') { throw ('内容扫描失败: ' + (@($r.errors) -join '; ')) }
  $cred = @($r.findings | Where-Object { $_.id -eq 'CRED' -and -not $_.doc })
  if ($cred.Count -eq 0) {
    [void]$lines.Add('[PASS] 内容: 未发现疑似密钥')
  } else {
    $failCount += $cred.Count
    foreach ($c in $cred) {
      [void]$lines.Add(('[FAIL] 内容: ' + $c.text + ' | ' + $c.file + ':' + $c.line))
    }
  }

  # 4) git 历史疑似密钥（复用与 -GitHistory 相同的密钥模式；不可用时显式 SKIP）
  if (-not $git) {
    [void]$lines.Add('[SKIP] git 历史: 未找到 git，无法检查历史残留')
    $skipCount++
  } elseif (-not $repoRoot) {
    [void]$lines.Add('[SKIP] git 历史: 目标不在 git 仓库内，无法检查历史残留（文件清单已按全目录检查）')
    $skipCount++
  } else {
    $histCred = New-Object System.Collections.ArrayList
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
      $secRe = 'sk-[A-Za-z0-9_\-]{20,}|ghp_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|-----BEGIN[^-]+PRIVATE\s+KEY-----|xox[baprs]-[A-Za-z0-9\-]{20,}'
      $seenSecret = @{}
      foreach ($line in @(& $git -C $repoRoot log --all -p -n $GitDepth 2>$null)) {
        foreach ($m in [regex]::Matches($line, $secRe)) {
          if (-not $seenSecret.ContainsKey($m.Value)) {
            $seenSecret[$m.Value] = $true
            [void]$histCred.Add((Get-MaskedText $m.Value))
          }
        }
      }
    } catch {
      [void]$lines.Add('[SKIP] git 历史: 检查失败: ' + $_.Exception.Message)
      $skipCount++
    } finally {
      $ErrorActionPreference = $prevEap
    }
    if (@($histCred).Count -eq 0) {
      [void]$lines.Add('[PASS] git 历史: 最近 ' + $GitDepth + ' 次提交未发现疑似密钥')
    } else {
      $failCount += @($histCred).Count
      foreach ($h in @($histCred)) {
        [void]$lines.Add(('[FAIL] git 历史: 疑似密钥（值已隐藏）: ' + $h))
      }
    }
  }

  if ($failCount -gt 0) {
    [void]$lines.Add(('结论: 发现 ' + $failCount + ' 项风险，不建议推送（仅提醒，不自动拦截）'))
  } else {
    $skipTxt = if ($skipCount -gt 0) { ('；' + $skipCount + ' 项未检查（见上）') } else { '' }
    [void]$lines.Add(('结论: 未发现泄露风险（检查 ' + $checkedFiles + ' 个文件' + $skipTxt + '）'))
  }
  foreach ($l in $lines) { Write-Output $l }
  if ($failCount -gt 0) { exit 1 }
}

function Get-BriefRiskSummary {
  param($r)
  $risk = @($r.findings | Where-Object { -not $_.doc -and -not (Get-BriefView $_).hide })
  $crit = @($risk | Where-Object { (Get-BriefSeverity (Get-BriefView $_).severity) -eq 'critical' }).Count
  $susp = @($risk | Where-Object { (Get-BriefSeverity (Get-BriefView $_).severity) -eq 'suspicious' }).Count
  $info = @($risk | Where-Object { (Get-BriefSeverity (Get-BriefView $_).severity) -eq 'info' }).Count
  $ref = @($r.reference_findings).Count
  return ('🔴 ' + $crit + ' 严重 / 🟡 ' + $susp + ' 可疑 / 💡 ' + $info + ' 提示 / 📄 ' + $ref + ' 参考')
}

function Get-InferenceText {
  param([string]$ruleId)
  $map = @{
    DOWNLOAD_EXECUTE = '供应链攻击/远程代码执行'
    PUBLIC_IP_CALL = '绕过 DNS，通信对象可疑'
    EXFIL = '窃取凭证/数据'
    CREDENTIAL_REQUEST = '窃取凭证/数据'
    SECRET_ENV_READ = '窃取凭证/数据'
    CREDENTIAL_FILE_ACCESS = '窃取凭证/数据'
    SYSTEM_FILE_MODIFY = '权限提升/系统篡改'
    PRIVILEGE_ESCALATION = '权限提升/系统篡改'
    BROWSER_SESSION_ACCESS = '窃取会话/凭证'
    INSTALL_HOOK = '供应链投毒/代码执行'
    INSECURE_HTTP_CALL = '通信可被窃听/篡改'
    INTERNAL_NET_CALL = '可能探测内网，需人工确认'
    SSRF = '可能访问云元数据/内网，需人工确认'
    EVAL_EXEC = '潜在远程代码执行，需人工确认上下文'
    BASE64_DECODE = '可能用于隐藏载荷，需人工确认'
    OBFUSCATION = '可能隐藏恶意逻辑'
    UNDECLARED_INSTALL = '供应链/未声明行为'
  }
  if ($map.ContainsKey($ruleId)) { return $map[$ruleId] }
  return ''
}

function Get-RuleDesc {
  param([string]$ruleId)
  foreach ($r in @($registry.rules) + @($registry.hints)) {
    if ($r.rule_id -eq $ruleId) { return $r.description }
  }
  if ($descMap.ContainsKey($ruleId)) { return $descMap[$ruleId] }
  return $ruleId
}

function Get-BriefSeverity {
  param([string]$sev)
  switch ($sev) {
    'CRITICAL' { return 'critical' }
    'HIGH' { return 'critical' }
    'MEDIUM' { return 'suspicious' }
    'MED' { return 'suspicious' }
    'LOW' { return 'info' }
    default { return $sev }
  }
}

function Get-BriefView {
  # 简报投影视图：普通规则命中 → 简报规则 id/severity/desc/priority/category
  # SSRF 特判：metadata 特征保持 SSRF critical 显示（不投影）；普通内部/回环纯 IP 隐藏其 INTERNAL 投影（地址分类器已展示）
  param($f)
  if ($f.id -eq 'SSRF' -and -not $f.doc) {
    if ($f.text -match 'metadata\.|instance-data|169\.254\.169\.254') {
      return [pscustomobject]@{ id = $f.id; brief_id = $f.id; severity = $f.severity; desc = ''; priority = 0; category = ''; projected = $false; hide = $false }
    }
    if ($f.text -match '(?i)localhost') {
      # localhost 是回环域名：LOOPBACK_ACCESS 语义更精确，隐藏该 SSRF 的 INTERNAL_NET_CALL 投影（canonical SSRF 保留）
      return [pscustomobject]@{ id = $f.id; brief_id = $f.id; severity = $f.severity; desc = ''; priority = 0; category = ''; projected = $false; hide = $true }
    }
    foreach ($ip in @(Get-IpCandidates $f.text)) {
      $cls = Get-AddressClass $ip
      if ($cls -in @('private', 'loopback')) {
        return [pscustomobject]@{ id = $f.id; brief_id = $f.id; severity = $f.severity; desc = ''; priority = 0; category = ''; projected = $false; hide = $true }
      }
    }
  }
  if ($script:briefProjectionFrom -and $script:briefProjectionFrom.ContainsKey($f.id)) {
    $p = $script:briefProjectionFrom[$f.id]
    return [pscustomobject]@{ id = $f.id; brief_id = $p.brief_id; severity = $p.severity; desc = $p.description; priority = $p.priority; category = $p.category; projected = $true; hide = $false }
  }
  return [pscustomobject]@{ id = $f.id; brief_id = $f.id; severity = $f.severity; desc = ''; priority = 0; category = ''; projected = $false; hide = $false }
}

function Get-BriefMarks {
  param($f)
  $mark = if ($f.activity -eq 'active') { '【主动】' } elseif ($f.activity -eq 'passive') { '【被动】' } elseif ($f.activity -eq 'mixed') { '【混合】' } else { '【未知】' }
  if ($f.invocation -eq 'not_called') { $mark += '【未实际调用】' }
  elseif ($f.invocation -eq 'framework_entry') { $mark += '【入口】' }
  if ($f.execution -eq 'documented') { $mark += '【文档示例】' }
  return $mark
}

function Render-BriefOne {
  param($r)
  $lines = New-Object System.Collections.ArrayList
  if ($r.skill_name) { [void]$lines.Add('==== Skill: ' + $r.skill_name + '（' + $r.path + '）====') }
  else { [void]$lines.Add('==== Skill: ' + $r.path + ' ====') }
  $tt = if ($r.target_type) { $r.target_type } else { 'unknown' }
  [void]$lines.Add('▸ Target Type: ' + $tt)
  if ($tt -ne 'skill') { [void]$lines.Add('▸ Warning: not recognized as isolated skill（未识别为独立技能）') }
  [void]$lines.Add('▸ analysis_status: ' + $r.analysis_status)
  if ($r.engines) {
    $offEng = @($r.engines.PSObject.Properties | Where-Object { $_.Value -notin @('on', 'available') } | ForEach-Object { $_.Name + '=' + $_.Value })
    if ($offEng.Count -gt 0) { [void]$lines.Add('▸ 检查器状态: ' + ($offEng -join '、')) }
  }
  $bsText = if (@($r.behavior_summary).Count -gt 0) { @($r.behavior_summary) -join '、' } else { '未发现明显风险行为' }
  [void]$lines.Add('▸ 行为概要: ' + $bsText)
  [void]$lines.Add('▸ 风险摘要: ' + (Get-BriefRiskSummary $r))
  if ($r.severity -in @('HIGH', 'CRITICAL')) {
    [void]$lines.Add('▸ 隔离建议: 高风险，建议先在隔离环境复扫确认（Docker 容器或云端 GitHub Actions），确认前不要在本机安装/运行')
  }
  [void]$lines.Add('▸ 最坏情况 TOP 3:')
  if (@($r.top3).Count -eq 0) { [void]$lines.Add('  （无）') }
  else {
    foreach ($f in @($r.top3)) {
      $v = Get-BriefView $f
      $d = if ($v.projected) { $v.desc } else { Get-RuleDesc $f.id }
      $inf = Get-InferenceText $v.brief_id
      [void]$lines.Add(('  • [{0}] {1} {2} {3}:{4} {5} 置信度 {6} → {7}' -f (Get-BriefSeverity $v.severity), $v.brief_id, $d, $f.file, $f.line, (Get-BriefMarks $f), $f.confidence, $inf))
      [void]$lines.Add(('    证据: ' + $f.text))
    }
  }
  [void]$lines.Add('▸ 关联发现:')
  if (@($r.correlation_findings).Count -eq 0) { [void]$lines.Add('  （无）') }
  else {
    foreach ($cf in @($r.correlation_findings)) {
      [void]$lines.Add(('  • [{0}] {1} {2}' -f (Get-BriefSeverity $cf.severity), $cf.id, (Get-RuleDesc $cf.id)))
      [void]$lines.Add(('    结论: ' + $cf.text))
      $srcIds = @($cf.source_finding_id)
      if ($srcIds.Count -gt 0) { [void]$lines.Add(('    源发现: ' + ($srcIds -join ', '))) }
    }
  }
  [void]$lines.Add('▸ 详细发现:')
  $risk = @($r.findings | Where-Object { -not $_.doc -and $_.id -ne 'CREDENTIAL_LOOPBACK_COEXIST' -and -not (Get-BriefView $_).hide })
  if ($risk.Count -eq 0) { [void]$lines.Add('  （无）') }
  else {
    foreach ($f in $risk) {
      $v = Get-BriefView $f
      $d = if ($v.projected) { $v.desc } else { Get-RuleDesc $f.id }
      $inf = Get-InferenceText $v.brief_id
      [void]$lines.Add(('  • [{0}] {1} {2} {3}:{4} {5} 置信度 {6}' -f (Get-BriefSeverity $v.severity), $v.brief_id, $d, $f.file, $f.line, (Get-BriefMarks $f), $f.confidence))
      [void]$lines.Add(('    事实: ' + $f.text))
      if ($inf) { [void]$lines.Add(('    推断: ' + $inf)) }
    }
  }
  [void]$lines.Add('▸ 参考发现（不计入风险）:')
  if (@($r.reference_findings).Count -eq 0) { [void]$lines.Add('  （无）') }
  else {
    foreach ($f in @($r.reference_findings | Select-Object -First 20)) {
      $v = Get-BriefView $f
      [void]$lines.Add(('  • [{0}] {1} {2}:{3} [{4}] {5}' -f (Get-BriefSeverity $v.severity), $v.brief_id, $f.file, $f.line, $f.context, $f.text))
    }
  }
  [void]$lines.Add('▸ 依赖与文件发现:')
  if (@($r.dependency_findings).Count -eq 0 -and @($r.skipped).Count -eq 0) { [void]$lines.Add('  （无）') }
  else {
    foreach ($df in @($r.dependency_findings)) {
      [void]$lines.Add(('  • [{0}] {1} {2} {3}:{4} {5}' -f (Get-BriefSeverity $df.severity), $df.id, (Get-RuleDesc $df.id), $df.file, $df.line, $df.text))
    }
    foreach ($s in @($r.skipped)) {
      [void]$lines.Add(('  • [skip] ' + $s.file + ': ' + $s.reason))
    }
  }
  [void]$lines.Add('▸ 已审状态: ' + (Get-VerificationText $r.verification))
  if ($Score) {
    [void]$lines.Add(('▸ 自动评分（推断指标，不代表放行/拒绝）: score=' + $r.score + ' / ' + $r.severity))
  }
  return $lines
}

# ---------- 主流程 ----------
# 参数校验
if ($Score -and -not $Brief) {
  [Console]::Error.WriteLine('错误: -Score 仅在 -Brief 模式下有效')
  exit 2
}
if ($PrePublish) {
  if (-not $Path) {
    [Console]::Error.WriteLine('错误: -PrePublish 必须与 -Path <目录> 配对使用')
    exit 2
  }
  if ($AllInstalled -or $Dir -or $Json -or $Output -or $Brief -or $Score -or $Interactive -or $Parallel -or $Worker -or $MarkVerified -or $CheckDeps -or $RegistryStats -or $RebakeSelfHashes -or $InitBaseline -or $Baseline -or $ShowSuppressed) {
    [Console]::Error.WriteLine('错误: -PrePublish 不能与 -AllInstalled/-Dir/-Json/-Output/-Brief/-Score/-Interactive/-Parallel/-Worker/-MarkVerified/-CheckDeps/-RegistryStats/-RebakeSelfHashes/-InitBaseline/-Baseline/-ShowSuppressed 同时使用')
    exit 2
  }
  try {
    Invoke-PrePublishCheck (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    exit 0
  } catch {
    [Console]::Error.WriteLine('错误: ' + $_.Exception.Message)
    exit 2
  }
}
if ($MarkVerified) {
  if (-not $Path) {
    [Console]::Error.WriteLine('错误: -MarkVerified 必须与 -Path <skill> 配对使用')
    exit 2
  }
  if ($Brief -or $Score -or $Json -or $Output -or $Interactive) {
    [Console]::Error.WriteLine('错误: -MarkVerified 不能与 -Brief/-Score/-Json/-Output/-Interactive 同时使用')
    exit 2
  }
  try {
    Invoke-MarkVerified $MarkVerified
    exit 0
  } catch {
    [Console]::Error.WriteLine('错误: ' + $_.Exception.Message)
    exit 2
  }
}
if ($CheckDeps) { Write-CheckDeps; exit 0 }
if ($Interactive -and $Parallel) { $Interactive = $false }

try {
  $targets = Get-Targets
} catch {
  [Console]::Error.WriteLine('错误: ' + $_.Exception.Message)
  exit 2
}
# -Path 命中多技能集合且显式 -Interactive 时，先让用户选择要审核的技能（非交互模式自动全扫）
if ($script:PathScopeMode -eq 'multi-skill' -and $Interactive -and -not $Json -and -not $Worker -and @($targets).Count -gt 1) {
  Write-Host '检测到多个技能，选择要审核的目标：'
  for ($i = 0; $i -lt $targets.Count; $i++) {
    Write-Host ('  [{0}] {1}' -f ($i + 1), (Split-Path $targets[$i] -Leaf))
  }
  $sel = Read-Host '选择序号（逗号分隔可多选 / a 全部 / q 退出）'
  if ($sel -eq 'q') { exit 0 }
  if ($sel -ne 'a') {
    $idx = @($sel -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ })
    if ($idx.Count -gt 0) {
      $targets = @($idx | Where-Object { $_ -ge 1 -and $_ -le $targets.Count } | ForEach-Object { $targets[$_ - 1] } | Select-Object -Unique)
    }
  }
}
$reports = New-Object System.Collections.ArrayList
$hadError = $false
$global:baselineFp = @{}
$global:baselineManifests = @{}
if ($Baseline -and -not $InitBaseline) {
  if (-not (Test-Path -LiteralPath $Baseline)) {
    [Console]::Error.WriteLine('错误: 基线文件不存在: ' + $Baseline)
    $hadError = $true
  } else {
    $rawBl = Get-Content -Raw -Encoding UTF8 -LiteralPath $Baseline -ErrorAction SilentlyContinue
    if (-not $rawBl -or $rawBl -notmatch 'version:|findings:|manifests:') {
      [Console]::Error.WriteLine('错误: 基线文件格式不受支持或已损坏: ' + $Baseline)
      $hadError = $true
    } else {
      $bl = Read-Baseline $Baseline
      $global:baselineFp = $bl.Fp
      $global:baselineManifests = $bl.Manifests
    }
  }
}
if ($hadError) { exit 2 }

# 并行工作进程模式：只扫单个目标并输出 JSON 报告对象
if ($Worker) {
  $r = Invoke-TargetScan $targets[0]
  Write-Output ($r | ConvertTo-Json -Depth 8)
  exit 0
}

if ($Parallel -and $targets.Count -gt 1 -and -not $InitBaseline) {
  foreach ($jr in @(Invoke-ParallelScans -targetList $targets -script $scriptPath)) {
    [void]$reports.Add($jr)
    if ($jr.recommendation -eq '扫描失败') { $hadError = $true }
  }
} else {
  foreach ($t in $targets) {
    try {
      $r = Invoke-TargetScan $t
      [void]$reports.Add($r)
      if ($r.recommendation -eq '扫描失败') { $hadError = $true }
    } catch {
      $hadError = $true
      [Console]::Error.WriteLine('扫描失败: ' + $t + ' → ' + $_.Exception.Message)
    }
  }
}

if ($InitBaseline) {
  foreach ($r in $reports) {
    $bf = if ($Baseline) { $Baseline } else { Join-Path $r.root '.skillspector-baseline.yaml' }
    Write-BaselineFile $bf @($r.findings | Where-Object { -not $_.doc }) $r.root
    Write-Output ('基线已写入: ' + $bf)
  }
  exit 0
}

$outLines = New-Object System.Collections.ArrayList
if (-not $Brief) {
if ($AllInstalled) { [void]$outLines.Add('==== Installed Skills Audit ====') }
foreach ($r in $reports) {
  [void]$outLines.Add('==== 目标: ' + $r.path + ' ====')
  $tt = if ($r.target_type) { $r.target_type } else { 'unknown' }
  [void]$outLines.Add(('Target Type: ' + $tt))
  if ($r.skill_name) { [void]$outLines.Add(('Skill: ' + $r.skill_name)) }
  [void]$outLines.Add(('Path: ' + $r.path))
  if ($tt -ne 'skill') { [void]$outLines.Add('Warning: not recognized as isolated skill（未识别为独立技能）') }
  $eff = @($r.findings | Where-Object { -not $_.doc -and -not ($_.PSObject.Properties['suppressed'] -and $_.suppressed) })
  $docCount = @($r.findings | Where-Object { $_.doc }).Count
  $suppCount = @($r.suppressed).Count
  $sc = $r.severityCounts
  $scC = if ($sc) { [int]$sc.CRITICAL } else { 0 }
  $scH = if ($sc) { [int]$sc.HIGH } else { 0 }
  $scM = if ($sc) { [int]$sc.MEDIUM } else { 0 }
  $scL = if ($sc) { [int]$sc.LOW } else { 0 }
  if ($Full) {
    $sorted = @($r.findings | Sort-Object file, line, id)
    foreach ($f in $sorted) {
      $isSupp = ($f.PSObject.Properties['suppressed'] -and $f.suppressed)
      $tag = '[' + $f.context + ']'
      if ($isSupp) {
        if (-not $ShowSuppressed) { continue }
        $tag = $tag + ' (baseline 抑制)'
      }
      $fd = if ($f.desc) { $f.desc } else { '' }
      $ow = if ($f.owasp) { ' [OWASP ' + $f.owasp + ']' } else { '' }
      [void]$outLines.Add(('[{0}] {1} {2} {3}:{4} {5} {6}{7}' -f $f.id, $f.severity, $fd, $f.file, $f.line, $tag, $f.text, $ow))
    }
    foreach ($s in $r.skipped) {
      $sd = if ($s.desc) { $s.desc } else { $s.reason }
      [void]$outLines.Add(('[SKIP] ' + $s.file + ': ' + $sd))
    }
    foreach ($e in $r.errors) { [void]$outLines.Add(('[ERR] ' + $e)) }
    [void]$outLines.Add(('==== 小结: score={0} / {1}（{2}）| 有效 {3} | 文档语境 {4} | 基线抑制 {5} | 跳过 {6} | 错误 {7} ====' -f `
      $r.score, $r.severity, $r.recommendation, $eff.Count, $docCount, $suppCount, $r.skipped.Count, $r.errors.Count))
    if ($r.engines) {
      [void]$outLines.Add(('==== 检查器: ' + (@($r.engines.PSObject.Properties | ForEach-Object { $_.Name + '=' + $_.Value }) -join ' / ')))
    }
  } else {
    [void]$outLines.Add(('▸ 结论: score={0} / {1}（{2}）| 有效 {3}（CRITICAL {4} / HIGH {5} / MED {6} / LOW {7}）' -f `
      $r.score, $r.severity, $r.recommendation, $eff.Count, $scC, $scH, $scM, $scL))
    $plainTop = if ($r.topCategories -and @($r.topCategories).Count -gt 0) { @($r.topCategories)[0] } else { '' }
    $plainDesc = $plainTop
    if ($plainTop -match '^[^(]+\(([^)]+)\)') { $plainDesc = $matches[1] }
    if ($eff.Count -eq 0) {
      [void]$outLines.Add('▸ 通俗解读: 未发现风险点，可以正常使用。')
    } elseif ($r.severity -eq 'LOW') {
      [void]$outLines.Add(('▸ 通俗解读: 只有轻微问题（' + $plainDesc + '），一般可以正常使用。'))
    } elseif ($r.severity -eq 'MEDIUM') {
      [void]$outLines.Add(('▸ 通俗解读: 有需要注意的问题（' + $plainDesc + '），建议复核后再用。'))
    } else {
      [void]$outLines.Add(('▸ 通俗解读: 存在严重问题（' + $plainDesc + '），不建议安装。'))
      [void]$outLines.Add('▸ 隔离建议: 高风险，建议先在隔离环境复扫确认（Docker 容器或云端 GitHub Actions），确认前不要在本机安装/运行')
    }
    if ($r.topCategories -and @($r.topCategories).Count -gt 0) {
      [void]$outLines.Add('▸ 重点类别: ' + (@($r.topCategories) -join '、'))
    }
    if ($r.topFindings -and @($r.topFindings).Count -gt 0) {
      [void]$outLines.Add('▸ 关键发现:')
      foreach ($tf in @($r.topFindings)) {
        $lineTxt = [string]$tf.text
        if ($lineTxt.Length -gt 100) { $lineTxt = $lineTxt.Substring(0, 100) + '…' }
        $fd = if ($tf.desc) { $tf.desc } else { '' }
        [void]$outLines.Add(('  • [{0}] {1} {2} {3}:{4} {5}' -f $tf.severity, $tf.id, $fd, $tf.file, $tf.line, $lineTxt))
      }
    }
    [void]$outLines.Add(('▸ 需人工确认: 文档语境 {0} · 跳过 {1} · 分析器错误 {2} · 基线抑制 {3}' -f $docCount, $r.skipped.Count, $r.errors.Count, $suppCount))
    if ($r.engines) {
      $offEng = @($r.engines.PSObject.Properties | Where-Object { $_.Value -notin @('on', 'available') } | ForEach-Object { $_.Name + '=' + $_.Value })
      if ($offEng.Count -gt 0) { [void]$outLines.Add(('▸ 检查器状态: ' + ($offEng -join '、'))) }
    }
    if ($r.errors -and @($r.errors).Count -gt 0) {
      foreach ($e in @($r.errors)) { [void]$outLines.Add(('  [ERR] ' + $e)) }
    }
    if ($ShowSuppressed -and $suppCount -gt 0) {
      [void]$outLines.Add('▸ 已抑制（baseline）:')
      foreach ($f in @($r.findings | Where-Object { $_.PSObject.Properties['suppressed'] -and $_.suppressed } | Sort-Object file, line)) {
        [void]$outLines.Add(('  • [{0}] {1} {2}:{3} {4}' -f $f.severity, $f.id, $f.file, $f.line, $f.text))
      }
    }
    [void]$outLines.Add('▸ 完整明细: 加 -Full 查看；-Json 输出机器可读 JSON')
  }
}

if ($reports.Count -gt 1) {
  [void]$outLines.Add('==== 批量汇总（按 score 降序）====')
  $mark = if ($AllInstalled) { '✓ ' } else { '' }
  foreach ($r in @($reports | Sort-Object -Property { $_.score } -Descending)) {
    $eff = @($r.findings | Where-Object { -not $_.doc -and -not ($_.PSObject.Properties['suppressed'] -and $_.suppressed) }).Count
    $sc = $r.severityCounts
    $scC = if ($sc) { [int]$sc.CRITICAL } else { 0 }
    $scH = if ($sc) { [int]$sc.HIGH } else { 0 }
    $scM = if ($sc) { [int]$sc.MEDIUM } else { 0 }
    $scL = if ($sc) { [int]$sc.LOW } else { 0 }
    $top1 = if ($r.topCategories -and @($r.topCategories).Count -gt 0) { @($r.topCategories)[0] } else { '-' }
    $sn = if ($r.skill_name) { $r.skill_name } else { $r.path }
    [void]$outLines.Add(($mark + '{0} | {1} | {2} | {3} | 有效 {4} | C{5}/H{6}/M{7}/L{8} | 重点 {9} | 跳过 {10}' -f `
      $sn, $r.score, $r.severity, $r.recommendation, $eff, $scC, $scH, $scM, $scL, $top1, $r.skipped.Count))
  }
}
[void]$outLines.Add('==== 扫描完成 ====')
} else {
  # ===== 简报模式输出 =====
  if ($reports.Count -eq 1) {
    foreach ($l in @(Render-BriefOne $reports[0])) { [void]$outLines.Add($l) }
  } else {
    $n = 0
    foreach ($r in $reports) {
      $n++
      $sn = if ($r.skill_name) { $r.skill_name } else { '-' }
      $tt = if ($r.target_type) { $r.target_type } else { 'unknown' }
      [void]$outLines.Add(('[{0}] {1} | type={2} | skill={3} | status={4} | {5} | {6}' -f $n, $r.path, $tt, $sn, $r.analysis_status, (Get-BriefRiskSummary $r), (Get-VerificationText $r.verification)))
    }
    if ($Interactive) { [void]$outLines.Add('输入序号查看详情，all 全部展开，q 退出') }
  }
  [void]$outLines.Add('==== 扫描完成 ====')
}

# 简报交互模式：多目标总览后按序号查看（单目标忽略；与 -Parallel 同用已在参数校验阶段关闭）
if ($Brief -and $Interactive -and -not $Json -and $reports.Count -gt 1) {
  while ($true) {
    $sel = Read-Host '选择序号（all 全部 / q 退出）'
    if ($sel -eq 'q') { break }
    if ($sel -eq 'all') {
      foreach ($r in $reports) { foreach ($l in @(Render-BriefOne $r)) { Write-Output $l } }
    } elseif ($sel -match '^\d+$') {
      $idx = [int]$sel
      if ($idx -ge 1 -and $idx -le $reports.Count) {
        foreach ($l in @(Render-BriefOne $reports[$idx - 1])) { Write-Output $l }
      } else { Write-Output ('序号无效: ' + $sel) }
    } else { Write-Output ('输入无效: ' + $sel) }
  }
}

if ($Json) {
  $runTs = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
  $ledger = New-InspectionLedger -targets @($reports) -runTs $runTs -scannerV $scannerVersion -rulesV ([string]$registry.rules_version) -policyV $policyVersion
  $jsonObj = [ordered]@{
    version = 1
    generated = (Get-Date -Format o)
    audit = [ordered]@{ inspection_run_id = $ledger.run_id; audit_root = $null }
    inspection = @($ledger.entries)
    targets = @($reports)
  }
  $content = $jsonObj | ConvertTo-Json -Depth 8
  if ($Output) {
    [System.IO.File]::WriteAllText($Output, $content, (New-Object System.Text.UTF8Encoding($false)))
    Write-Output ('JSON 报告已写入: ' + $Output)
  } else {
    Write-Output $content
  }
} else {
  $content = $outLines -join "`r`n"
  if ($Output) {
    [System.IO.File]::WriteAllText($Output, $content, (New-Object System.Text.UTF8Encoding($false)))
    Write-Output ('文本报告已写入: ' + $Output)
  } else {
    foreach ($l in $outLines) { Write-Output $l }
  }
}

$maxScore = 0
foreach ($r in $reports) { if ($r.score -gt $maxScore) { $maxScore = $r.score } }
if ($hadError) { exit 2 }
if ($maxScore -gt 50) { exit 1 }
exit 0
