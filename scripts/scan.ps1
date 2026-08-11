<#
.SYNOPSIS
  skillspector-scan 静态扫描引擎（只读，不执行目标技能的任何脚本）

.DESCRIPTION
  对技能目录 / 单个文件 / .zip 做静态安全检查：
  - 单遍读取文本文件，自动探测编码（UTF-8 BOM / UTF-16 / 严格 UTF-8 / GBK 兜底）
  - 29 组行级正则 + 多行恶意特征 + base64 载荷解码复查
  - 命中按语境标注：code（代码）/ config（配置）/ doc（文档）/ data（数据），
    文档语境（.md、代码围栏）自动标记为可排除，降低误报
  - 自动检查：依赖是否锁定版本（requirements/Pipfile/pyproject/package.json）、
    SKILL.md frontmatter、.env 真实凭据、符号链接/联接越界、
    Python AST 危险调用与轻量污点（自动探测 python；-NoAst 关闭）
  - 可选 OSV.dev 已知漏洞查询（-CheckCVE，联网；失败自动降级为离线）
  - 可选 baseline 误报抑制（-InitBaseline / -Baseline / -ShowSuppressed）
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
.PARAMETER UpdateRules
  从指定源更新检测规则（“毒库”）：https:// URL 或本地文件路径；更新前自动备份旧规则
.PARAMETER ShowRules
  显示当前检测规则的版本、来源与时效
.PARAMETER RulesFile
  指定规则文件路径（默认读取技能目录下 rules/patterns.json；用于测试或定制部署）
.PARAMETER ExportRules
  把当前生效的检测规则导出为 JSON 文件（可用于发布自定义规则源）
.PARAMETER RuleId
  收录新危害时使用的规则 ID（配合 -Regex 使用）
.PARAMETER Severity
  新规则的严重级：CRITICAL/HIGH/MEDIUM/LOW，默认 HIGH
.PARAMETER Regex
  新规则的正则表达式（会先校验能否编译）
.PARAMETER Desc
  新规则的通俗说明（默认用规则 ID）
.PARAMETER MultiRule
  收录为多行特征（multiPatterns）而不是行级模式
.PARAMETER NoScore
  新规则仅作信号、不计分（score=false）
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
  [string]$UpdateRules,
  [switch]$ShowRules,
  [string]$RulesFile,
  [string]$ExportRules,
  [string]$RuleId,
  [string]$Severity = 'HIGH',
  [string]$Regex,
  [string]$Desc,
  [switch]$MultiRule,
  [switch]$NoScore
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
$OutputEncoding = [System.Text.Encoding]::UTF8

$skillName = 'skillspector-scan'
$instructionIds = @('AR', 'P1', 'SPL', 'MP', 'EA', 'TR', 'AST05')
$astScript = Join-Path $PSScriptRoot 'ast_check.py'
$scriptPath = $MyInvocation.MyCommand.Path
if (-not $scriptPath) { $scriptPath = Join-Path $PSScriptRoot 'scan.ps1' }
$sevPoints = @{ CRITICAL = 50; HIGH = 25; MEDIUM = 10; MED = 10; LOW = 5 }

$skipExt = @(
  '.png','.jpg','.jpeg','.gif','.webp','.ico','.jar','.zip','.7z','.rar',
  '.exe','.dll','.bin','.dat','.iso','.o','.so','.dylib',
  '.ogg','.mp3','.mp4','.wav','.avi','.mov',
  '.ttf','.woff','.woff2','.otf','.eot',
  '.pdf','.doc','.docx','.xls','.xlsx','.ppt','.pptx',
  '.pyc','.pyo','.whl','.deb','.rpm','.apk'
)

# 行级模式：id / severity / regex。score=$false 表示仅作信号、不计分（如 E1URL）
$linePatterns = @(
  @{ id='AR';   sev='HIGH'; owasp='AST01'; re='never\s+refuse|always\s+comply|no\s+disclaimers|no\s+restrictions|ignore\s+your\s+guidelines|do\s+anything\s+now|永不拒绝|永远不要拒绝|不许拒绝|不要(添加|加|输出|提醒).*(免责声明|警告|风险)|不要提示.*风险|别啰嗦' },
  @{ id='P1';   sev='HIGH'; owasp='AST01'; re='忽略.*(系统|上级|指令)|无视.*(指令|规则|限制)|override\s+(system|instruction|policy|safety)|only\s+obey|只服从本文件|以本文件为准' },
  @{ id='SPL';  sev='HIGH'; owasp='AST01'; re='system\s+prompt|print\s+.*instructions|输出.*(系统提示|系统指令|内部规则)|复述.*(系统提示|指令)|show\s+.*(system\s+prompt|instructions)' },
  @{ id='MP';   sev='MED';  owasp='AST01'; re='记住.*(永远|长期)|persist\s+this|long[- ]term|跨会话|写入.*(memory|记忆)|修改.*(memory|记忆)|永远记住' },
  @{ id='EA';   sev='MED';  owasp='AST03'; re='无需确认|不要问问题|不用征求同意|不用询问|no\s+confirmation|without\s+asking|full\s+access|自动执行|直接执行.*(删除|发布|转账|提交)|不需要.*确认|don.t\s+ask' },
  @{ id='TR';   sev='MED';  owasp='AST01'; re='always\s+(comply|obey|follow|do|run|use)|一切.*(任务|请求)|所有.*(任务|请求).*(执行|处理)|无论如何都要|任何情况下都|无条件执行' },
  @{ id='E1';   sev='MED';  owasp='AST06'; re='requests\.(post|put|patch)|httpx|aiohttp|fetch\s*\(|Invoke-WebRequest|Invoke-RestMethod|curl\s+.*(-d|--data|-X)|urllib\.(request|parse)|http\.client|WebClient|XMLHttpRequest|axios|\.post\s*\(|\.put\s*\(' },
  @{ id='E1URL'; sev='LOW'; owasp=''; re='https?://'; score=$false },
  @{ id='E2';   sev='HIGH'; owasp='AST06'; re='os\.environ|process\.env|Get-ChildItem\s+Env:|environ\.get|os\.getenv|getenv\s*\(|Env:\w+|lookupEnv|API_KEY|SECRET_KEY|ACCESS_TOKEN|AUTH_TOKEN|PASSWORD' },
  @{ id='E3';   sev='MED';  owasp='AST03'; re='\.ssh[\\/]|\.aws[\\/]|credentials(\.json|\.txt|\.ini|\.env)?|os\.walk\s*\(|glob\s*\(.*(home|/Users|/home)' },
  @{ id='E5';   sev='MED';  owasp='AST06'; re='put_object|upload_file|s3\s+cp|gsutil|upload_blob|UploadFromFile|copy_object' },
  @{ id='SSRF'; sev='HIGH'; owasp='AST06'; re='169\.254\.169\.254|metadata\.google|metadata\.compute|instance-data|127\.0\.0\.1|localhost|192\.168\.|10\.\d+\.\d+\.\d+' },
  @{ id='AS';   sev='HIGH'; owasp='AST03'; re='\.claude[\\/]|\.codex[\\/]|\.gemini[\\/]|mcp\.json|credentials\.json' },
  @{ id='DC';   sev='HIGH'; owasp='AST01'; re='\bexec\s*\(|\beval\s*\(|\bcompile\s*\(|__import__\s*\(|os\.system\s*\(|subprocess\s*\.|Popen\s*\(|Invoke-Expression|\bIEX\b|child_process|execSync|new\s+Function\s*\(|System\.Diagnostics\.Process|Start-Process' },
  @{ id='DC7';  sev='MED';  owasp='AST01'; re='getattr\s*\([^,]+,\s*(?!\s*[\x22\x27])' },
  @{ id='SC2';  sev='HIGH'; owasp='AST02'; re='curl\s+.*\|\s*(ba)?sh|wget\s+.*\|\s*(ba)?sh|irm\s+.*\|\s*iex|iwr\s+.*\|\s*iex|DownloadString|DownloadFile|Invoke-Expression\s*\([^)]*http' },
  @{ id='SC3';  sev='HIGH'; owasp='AST01'; re='b64decode\s*\(|Convert\.FromBase64String|FromBase64\s*\(|-?enc\s+[A-Za-z0-9+/=]{16,}' },
  @{ id='RA';   sev='HIGH'; owasp='AST03'; re='crontab\s*(-e)?|schtasks|Startup[\\/]|launchd|systemd|\.bashrc|\.zshrc|\.profile|HKCU:|CurrentVersion[\\/]Run|reg\s+add.*Run|Set-ItemProperty.*Run|New-ScheduledTask' },
  @{ id='PE';   sev='MED';  owasp='AST03'; re='sudo\s|runas\s|--no-sandbox|--insecure|-ExecutionPolicy\s+Bypass|Set-ExecutionPolicy|Bypass\s*=\s*true|requireAdministrator|admin:\s*true|elevat' },
  @{ id='TM';   sev='MED';  owasp='AST03'; re='shell\s*=\s*True|--force\b|--yes\b|-y\b|privileged:\s*true|hostPath|--no-verify|--unsafe-perm|--allow-root' },
  @{ id='DEL';  sev='HIGH'; owasp='AST01'; re='rm\s+-rf|Remove-Item\s+.*-Recurse|-Recurse\s+.*Remove-Item|del\s+/s|rmdir\s+/s|shutil\.rmtree|os\.remove|os\.unlink' },
  @{ id='CRED'; sev='HIGH'; owasp='AST01'; re='sk-[A-Za-z0-9_\-]{20,}|ghp_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|-----BEGIN[^-]+PRIVATE\s+KEY-----|xox[baprs]-[A-Za-z0-9\-]{20,}' },
  @{ id='YR1';  sev='HIGH'; owasp='AST01'; re='bash\s+-i|/dev/tcp/|nc\s+-e|ncat\s+-e|socat\s+tcp|reverse\s+shell|meterpreter|webshell|antsword|冰蝎|哥斯拉' },
  @{ id='YR2';  sev='HIGH'; owasp='AST01'; re='<\?php[^\r\n]*(eval|assert|system|shell_exec)\s*\(|eval\s*\(\s*\S*_POST|eval\s*\(\s*\S*_REQUEST|cmd\s+/c|powershell\s+(-enc|-e)\s+[A-Za-z0-9+/=]{8,}' },
  @{ id='YR3';  sev='HIGH'; owasp='AST01'; re='stratum|xmrig|minergate|nicehash|cryptonight' },
  @{ id='YR4';  sev='HIGH'; owasp='AST01'; re='metasploit|sqlmap|nuclei\s+-t|nikto|hydra\s+-l|masscan|beef-xss' },
  @{ id='OBS';  sev='MED';  owasp='AST04'; re='b64decode\s*\(|atob\s*\(|btoa\s*\(|FromBase64|\\x[0-9a-f]{2}|\\u[0-9a-f]{4}' },
  @{ id='ZW';   sev='MED';  owasp='AST04'; re='[\u200b\u200c\u200d\u2060\ufeff\u202e]' },
  @{ id='AST05'; sev='HIGH'; owasp='AST05'; re='(?i)(?:fetch|retrieve|read|download|get|curl|visit|open|access|follow|obey|execute|按|照|根据|遵循|遵从|听从|读取|获取|访问|下载|抓取|执行)(?:[^\r\n]{0,80}?)(?:https?://[^\s\r\n]{1,80})(?:[^\r\n]{0,40}?)(?:instructions?|directives?|guidelines?|rules|commands?|指令|指示|规则)|(?:fetch|retrieve|read|download|get|follow|obey|execute|读取|获取|访问|下载)(?:[^\r\n]{0,40}?)(?:instructions?|directives?|guidelines?|rules|commands?|指令|指示|规则)(?:[^\r\n]{0,40}?)(?:from|at|on)?\s*https?://[^\s\r\n]{1,80}|https?://[^\s\r\n]{1,80}[^\r\n]{0,40}(?:获取|读取|下载|fetch|read|download|retrieve)[^\r\n]{0,40}(?:指令|指示|规则|instructions?|directives?)|(?:把|将|treat|consider|regard)[^\r\n]{0,30}(?:网页|页面|网站|内容|content|page|website|url|链接|文件)[^\r\n]{0,30}(?:当作|视为|作为|as)[^\r\n]{0,30}(?:指令|指示|规则|instructions?|directives?|guidelines?|rules)' }
)

# 多行特征（对整文件文本匹配，兼容跨行写法）
$multiPatterns = @(
  @{ id='YRM'; sev='HIGH'; owasp='AST01'; re='(?s)bash\s+-i\s+>&?\s*/dev/tcp/' },
  @{ id='YRM'; sev='HIGH'; owasp='AST01'; re='(?s)(python|perl|ruby)\s+-c\s+[\x22\x27][^\x22\x27]{0,300}(socket|pty|exec|base64)' },
  @{ id='YRM'; sev='HIGH'; owasp='AST01'; re='(?s)powershell[^\r\n]{0,150}\s+(-enc|-e)\s+[A-Za-z0-9+/=]{20,}' },
  @{ id='YRM'; sev='HIGH'; owasp='AST01'; re='(?s)curl\s+[^\r\n]{0,200}\s*\|\s*(ba)?sh' },
  @{ id='YRM'; sev='HIGH'; owasp='AST01'; re='(?s)wget\s+[^\r\n]{0,200}\s*\|\s*(ba)?sh' }
)

# 每个检测项的通俗说明（给报告读者看，不解释代号，直接说人话）
$descMap = @{
  AR     = '要求“永不拒绝/绕过限制”'
  P1     = '试图覆盖或忽略指令'
  SPL    = '诱导泄露系统提示'
  MP     = '试图长期篡改记忆/上下文'
  EA     = '过度自主执行、绕过确认'
  TR     = '触发词过于宽泛'
  E1     = '向外部发送数据'
  E1URL  = '外部网络地址（信号）'
  E2     = '读取环境变量/密钥'
  E3     = '扫描敏感文件/目录'
  E5     = '上传到云存储'
  SSRF   = '访问内网或云元数据地址'
  AS     = '窥探其他代理配置'
  DC     = '危险代码调用（执行命令/动态执行）'
  DC7    = '动态属性访问'
  DC8    = '非字面量动态执行'
  DC4    = '执行外部进程'
  SC1    = '依赖未锁定版本'
  SC2    = '远程下载并执行'
  SC3    = '混淆/编码后执行'
  SC4    = '依赖存在已知漏洞'
  RA     = '持久化/开机自启'
  PE     = '提权或绕过限制'
  TM     = '工具参数滥用'
  DEL    = '删除类危险操作'
  CRED   = '疑似密钥/凭据'
  YR1    = '恶意特征（反弹shell/木马）'
  YR2    = '恶意特征（webshell）'
  YR3    = '恶意特征（挖矿）'
  YR4    = '恶意特征（攻击工具）'
  YRM    = '多行恶意特征'
  OBS    = '混淆内容（base64等）'
  ZW     = '隐藏不可见字符'
  MD     = '元数据/命名问题'
  SYMLINK = '链接指向技能目录外'
  RP     = '安装后清单被改动（rug-pull）'
  TT3    = '密钥/凭据流向网络'
  TT5    = '外部输入流入代码执行'
  AST05  = '外部指令来源（诱导从远程地址获取指令）'
}

# OWASP Agentic Skills Top 10 启发式映射（官方分类：AST01 恶意技能 / AST02 供应链 /
# AST03 过度权限 / AST04 元数据不可信 / AST05 外部指令来源 / AST06 隔离不足 / AST07 更新漂移）。
# 由规则文件中的 owasp 字段覆盖；未标注的检测项（如纯信号 E1URL）不映射。
$owaspMap = @{
  AR='AST01'; P1='AST01'; SPL='AST01'; MP='AST01'; TR='AST01'; EA='AST03'
  E1='AST06'; E2='AST06'; E3='AST03'; E5='AST06'; SSRF='AST06'; AS='AST03'
  DC='AST01'; DC7='AST01'; SC2='AST02'; SC3='AST01'; RA='AST03'; PE='AST03'; TM='AST03'
  DEL='AST01'; CRED='AST01'; YR1='AST01'; YR2='AST01'; YR3='AST01'; YR4='AST01'; YRM='AST01'
  OBS='AST04'; ZW='AST04'; MD='AST04'; SYMLINK='AST06'; RP='AST07'; SC1='AST02'; SC4='AST02'
  DC4='AST01'; DC8='AST01'; TT3='AST06'; TT5='AST06'; AST05='AST05'
}

# ---------- 检测规则（“毒库”）加载与更新 ----------
$rulesMeta = @{ version = '1.0.0'; updated = '2026-08-10'; source = '内置出厂规则'; patternCount = ($linePatterns.Count + $multiPatterns.Count) }
$rulesFromFile = $false

function Get-RulesPath {
  if ($RulesFile) { return (Resolve-Path -LiteralPath $RulesFile -ErrorAction SilentlyContinue).Path }
  return Join-Path (Split-Path $PSScriptRoot -Parent) 'rules\patterns.json'
}

function Get-LoadedRules {
  # 加载外部规则文件（rules/patterns.json 或 -RulesFile）；失败/缺失时回退内置出厂规则
  $path = Get-RulesPath
  if (-not $path -or -not (Test-Path -LiteralPath $path)) { return $false }
  try {
    $o = Get-Content -Raw -Encoding UTF8 -LiteralPath $path -ErrorAction Stop | ConvertFrom-Json
    if (-not $o.version -or -not $o.linePatterns -or @($o.linePatterns).Count -lt 5) { throw '规则文件缺少 version 或 linePatterns 过少' }
    $script:linePatterns = @($o.linePatterns | ForEach-Object {
      [pscustomobject]@{ id = $_.id; sev = $_.severity; re = $_.regex; score = if ($_.PSObject.Properties['score']) { [bool]$_.score } else { $true }; owasp = if ($_.PSObject.Properties['owasp']) { [string]$_.owasp } else { '' } }
    })
    $script:multiPatterns = @($o.multiPatterns | ForEach-Object {
      [pscustomobject]@{ id = $_.id; sev = $_.severity; re = $_.regex; owasp = if ($_.PSObject.Properties['owasp']) { [string]$_.owasp } else { '' } }
    })
    $script:descMap = @{}
    foreach ($kv in @($o.descMap.PSObject.Properties)) { $script:descMap[$kv.Name] = [string]$kv.Value }
    # 规则文件里的 owasp 字段优先；未标注的检测项保留内置启发式映射
    foreach ($p in @($o.linePatterns) + @($o.multiPatterns)) {
      if ($p.PSObject.Properties['owasp'] -and $p.owasp) { $script:owaspMap[[string]$p.id] = [string]$p.owasp }
    }
    $script:rulesMeta = @{
      version = [string]$o.version
      updated = [string]$o.updated
      source  = [string]$o.source
      patternCount = @($o.linePatterns).Count + @($o.multiPatterns).Count
    }
    $script:rulesFromFile = $true
    return $true
  } catch {
    Write-Output ('警告: 规则文件解析失败，回退内置出厂规则: ' + $_.Exception.Message)
    return $false
  }
}

function Update-RulesFromSource {
  param([string]$source)
  if ($source -match '^https://') {
    try {
      $content = (Invoke-WebRequest -Uri $source -UseBasicParsing -TimeoutSec 30).Content
    } catch {
      throw '下载规则失败（网络不可用或地址无效）: ' + $_.Exception.Message
    }
  } elseif ($source -match '^file://') {
    $local = $source -replace '^file://', ''
    if (-not (Test-Path -LiteralPath $local)) { throw '本地规则文件不存在: ' + $local }
    $content = Get-Content -Raw -Encoding UTF8 -LiteralPath $local
  } elseif (Test-Path -LiteralPath $source) {
    $content = Get-Content -Raw -Encoding UTF8 -LiteralPath $source
  } else {
    throw '规则源仅支持 https:// URL 或本地文件路径'
  }
  # 格式校验（防损坏/防投毒），通过后才允许替换
  $o = $content | ConvertFrom-Json
  if (-not $o.version -or -not $o.linePatterns -or @($o.linePatterns).Count -lt 5) {
    throw '规则文件格式无效（缺少 version/linePatterns 或模式过少），已放弃更新'
  }
  $rulesDir = Join-Path (Split-Path $PSScriptRoot -Parent) 'rules'
  if (-not (Test-Path -LiteralPath $rulesDir)) { New-Item -ItemType Directory -Force -Path $rulesDir | Out-Null }
  $target = Join-Path $rulesDir 'patterns.json'
  $bakName = 'patterns.json.bak-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
  if (Test-Path -LiteralPath $target) { Copy-Item -LiteralPath $target (Join-Path $rulesDir $bakName) -Force }
  [System.IO.File]::WriteAllText($target, $content, (New-Object System.Text.UTF8Encoding($false)))
  $sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $target).Hash
  Write-Output ('规则已更新: version=' + $o.version + ' 模式数=' + (@($o.linePatterns).Count + @($o.multiPatterns).Count) + ' 来源=' + $o.source)
  Write-Output ('SHA256=' + $sha + '（旧规则已备份为 rules\' + $bakName + '）')
}

function Show-RulesInfo {
  $path = Get-RulesPath
  $used = if ($rulesFromFile) { '规则文件已加载（来源: ' + $rulesMeta.source + '）' } else { '内置出厂规则（无外部规则文件或加载失败）' }
  Write-Output ('检测规则: version=' + $rulesMeta.version + ' 更新日期=' + $rulesMeta.updated + ' 模式数=' + $rulesMeta.patternCount)
  Write-Output ('规则来源: ' + $used)
  if ($path -and (Test-Path -LiteralPath $path)) { Write-Output ('规则文件: ' + $path) }
  $mapped = @($owaspMap.GetEnumerator() | Where-Object { $_.Key -and $_.Value }).Count
  Write-Output ('OWASP 映射: ' + $mapped + ' 个检测项已关联 OWASP Agentic Skills 分类（AST01 恶意技能 / AST03 过度权限 / AST05 外部指令来源 / AST06 隔离不足 等）')
  try {
    $age = (New-TimeSpan -Start ([datetime]::Parse($rulesMeta.updated)) -End (Get-Date)).Days
    if ($age -gt 30) { Write-Output ('提示: 规则已 ' + $age + ' 天未更新，可运行 -UpdateRules <https://...> 更新') }
  } catch {}
}

function Add-RuleEntry {
  # 收录新危害：把一条规则写入当前毒库（默认 rules/patterns.json，可用 -RulesFile 指定）
  if ($RuleId -notmatch '^[A-Za-z0-9_\-]{1,20}$') { throw '规则 ID 不合法（限字母/数字/_/-，不超过 20 字符）' }
  if ($Severity -eq 'MED') { $Severity = 'MEDIUM' }
  if ($Severity -notin @('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')) { throw '严重级必须是 CRITICAL/HIGH/MEDIUM/LOW' }
  try { [void][regex]::new($Regex) } catch { throw '正则无法编译，已放弃收录: ' + $_.Exception.Message }
  $path = Get-RulesPath
  if (-not $path -or -not (Test-Path -LiteralPath $path)) {
    # 尚无规则文件：先用当前生效规则生成一份
    $path = if ($RulesFile) { $RulesFile } else { Join-Path (Split-Path $PSScriptRoot -Parent) 'rules\patterns.json' }
    $dir = Split-Path $path -Parent
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $o = [pscustomobject]@{
      version = $rulesMeta.version; updated = (Get-Date -Format 'yyyy-MM-dd'); source = $rulesMeta.source
      linePatterns = @($linePatterns | ForEach-Object { [pscustomobject]@{ id = $_.id; severity = $_.sev; regex = $_.re; score = if ($_.PSObject.Properties['score']) { [bool]$_.score } else { $true }; owasp = if ($_.PSObject.Properties['owasp']) { [string]$_.owasp } else { '' } } })
      multiPatterns = @($multiPatterns | ForEach-Object { [pscustomobject]@{ id = $_.id; severity = $_.sev; regex = $_.re; owasp = if ($_.PSObject.Properties['owasp']) { [string]$_.owasp } else { '' } } })
      descMap = $descMap
    }
    [System.IO.File]::WriteAllText($path, ($o | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
  }
  $bakName = $path + '.bak-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
  if (Test-Path -LiteralPath $path) { Copy-Item -LiteralPath $path $bakName -Force }
  $o = Get-Content -Raw -Encoding UTF8 -LiteralPath $path | ConvertFrom-Json
  $list = if ($MultiRule) { @($o.multiPatterns) } else { @($o.linePatterns) }
  $newList = New-Object System.Collections.ArrayList
  $found = $false
  foreach ($p in $list) {
    if ($p.id -eq $RuleId) {
      $found = $true
      $keepOwasp = if ($p.PSObject.Properties['owasp'] -and $p.owasp) { [string]$p.owasp } else { '' }
      [void]$newList.Add([pscustomobject]@{ id = $RuleId; severity = $Severity; regex = $Regex; score = (-not $NoScore); owasp = $keepOwasp })
    } else {
      [void]$newList.Add($p)
    }
  }
  if (-not $found) { [void]$newList.Add([pscustomobject]@{ id = $RuleId; severity = $Severity; regex = $Regex; score = (-not $NoScore); owasp = '' }) }
  if ($MultiRule) { $o.multiPatterns = @($newList) } else { $o.linePatterns = @($newList) }
  $dm = @{}
  if ($o.descMap) { foreach ($kv in @($o.descMap.PSObject.Properties)) { $dm[$kv.Name] = [string]$kv.Value } }
  $dm[$RuleId] = if ($Desc) { $Desc } else { $RuleId }
  $o.descMap = $dm
  $v = [string]$o.version
  if ($v -match '^(\d+)\.(\d+)\.(\d+)$') { $o.version = $matches[1] + '.' + $matches[2] + '.' + ([int]$matches[3] + 1) }
  else { $o.version = $v + '.1' }
  $o.updated = Get-Date -Format 'yyyy-MM-dd'
  [System.IO.File]::WriteAllText($path, ($o | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
  Write-Output ('已收录规则: ' + $RuleId + ' [' + $Severity + '] 正则=' + $Regex)
  Write-Output ('规则文件: ' + $path + '（版本 ' + $o.version + '，旧规则已备份 ' + $bakName + '）')
  [void](Get-LoadedRules)
}

[void](Get-LoadedRules)

function Get-SkillsRoot {
  if ($env:CODEX_HOME) { return Join-Path $env:CODEX_HOME 'skills' }
  $here = Split-Path $PSScriptRoot -Parent
  $root = Split-Path $here -Parent
  if ((Split-Path $here -Leaf) -eq $skillName) { return $root }
  return $null
}

function Get-Targets {
  $list = @()
  $modes = 0
  if ($AllInstalled) { $modes++ }
  if ($Path) { $modes++ }
  if ($Dir) { $modes++ }
  if ($modes -gt 1) { throw '请只使用 -Path / -AllInstalled / -Dir 中的一种' }
  if ($AllInstalled) {
    $root = Get-SkillsRoot
    if (-not $root) { throw '无法定位 skills 根目录，请改用 -Path 指定' }
    $list = @(Get-ChildItem -Directory -Force -LiteralPath $root |
      Where-Object { $_.Name -ne '.system' } | Select-Object -ExpandProperty FullName)
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
    $list = @($resolved.Path)
  } else {
    throw '请提供 -Path <技能目录|文件|zip>、-Dir <技能文件夹> 或使用 -AllInstalled'
  }
  return ,$list
}

function Read-TextFile {
  param([string]$path)
  $fs = [System.IO.File]::OpenRead($path)
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
      try { $text = [System.Text.Encoding]::GetEncoding(936).GetString($buf) }
      catch { $text = [System.Text.Encoding]::Default.GetString($buf) }
    }
  }
  $text = $text -replace "`r`n", "`n" -replace "`r", "`n"
  return [pscustomobject]@{ Text = $text; Encoding = $enc; Truncated = $truncated }
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
  param([string]$root, [switch]$IncludeDirs)
  $out = New-Object System.Collections.ArrayList
  $item = Get-Item -Force -LiteralPath $root -ErrorAction SilentlyContinue
  if (-not $item) { return $out }
  $queue = New-Object System.Collections.Queue
  $queue.Enqueue($item)
  while ($queue.Count -gt 0) {
    $dir = $queue.Dequeue()
    foreach ($child in @(Get-ChildItem -Force -LiteralPath $dir.FullName -ErrorAction SilentlyContinue)) {
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

function New-Finding {
  param($id, $severity, $file, $line, $text, $context, $doc, $score = $true)
  [pscustomobject]@{
    id       = $id
    desc     = if ($descMap.ContainsKey($id)) { $descMap[$id] } else { '' }
    owasp    = if ($owaspMap.ContainsKey($id)) { $owaspMap[$id] } else { '' }
    severity = $severity
    file     = $file
    line     = $line
    text     = (Get-MaskedText $text)
    context  = $context
    doc      = [bool]$doc
    score    = [bool]$score
  }
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
      [void]$out.Add((New-Finding -id 'OBS' -severity 'HIGH' -file $file -line $ln -text ('base64 载荷解码后含危险关键词: ' + $hit) -context $context -doc $doc))
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
        [void]$out.Add((New-Finding -id 'CRED' -severity 'HIGH' -file $envFile.FullName -line ($i + 1) -text ('.env 含疑似凭据变量: ' + $name + '（值已隐藏）') -context 'config' -doc $false))
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
      [void]$out.Add((New-Finding -id 'MD' -severity 'LOW' -file $metaFile.FullName -line 1 -text 'frontmatter 不完整（缺 name/description 或缺少 --- 包裹）' -context 'doc' -doc $false))
    } elseif ($nameVal -ne $folder) {
      [void]$out.Add((New-Finding -id 'MD' -severity 'LOW' -file $metaFile.FullName -line 1 -text ("name 与目录名不一致: $nameVal != $folder") -context 'doc' -doc $false))
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
      [void]$out.Add((New-Finding -id 'SYMLINK' -severity 'MED' -file $link.FullName -line 0 -text ('符号链接/联接指向技能目录外: -> ' + $target) -context 'data' -doc $false))
    }
  }
  return $out
}

function Get-DependencyFindings {
  param([string]$root)
  $out = New-Object System.Collections.ArrayList
  $cveCandidates = New-Object System.Collections.ArrayList
  $reqFiles = @(Get-ItemsSafe $root | Where-Object { $_.Name -match '^(requirements.*\.txt|Pipfile|environment\.ya?ml)$' })
  foreach ($rf in $reqFiles) {
    $lines = @(Get-Content -Encoding UTF8 -LiteralPath $rf.FullName -ErrorAction SilentlyContinue)
    for ($i = 0; $i -lt $lines.Count; $i++) {
      $l = $lines[$i].Trim()
      if ($l -eq '' -or $l.StartsWith('#') -or $l.StartsWith('[')) { continue }
      if ($l -match '^git\+https?://') {
        if ($l -notmatch '@[0-9a-fA-F]{7,}') {
          [void]$out.Add((New-Finding -id 'SC1' -severity 'LOW' -file $rf.FullName -line ($i + 1) -text ('git 依赖未锁定提交: ' + $l) -context 'config' -doc $false))
        }
        continue
      }
      if ($l -match '^([A-Za-z0-9_.\-]+)\s*(==|>=|<=|~=|!=|===|<|>)\s*([^\s;#]+)') {
        $pkg = $matches[1]; $op = $matches[2]; $ver = $matches[3]
        if ($op -eq '==' -or $op -eq '===') {
          [void]$cveCandidates.Add([pscustomobject]@{ eco = 'PyPI'; name = $pkg; version = $ver; file = $rf.FullName; line = $i + 1 })
        } else {
          [void]$out.Add((New-Finding -id 'SC1' -severity 'LOW' -file $rf.FullName -line ($i + 1) -text ("依赖未锁定版本: $pkg ($op$ver)") -context 'config' -doc $false))
        }
      } elseif ($l -match '^([A-Za-z0-9_.\-]+)\s*(#.*)?$') {
        [void]$out.Add((New-Finding -id 'SC1' -severity 'LOW' -file $rf.FullName -line ($i + 1) -text ('依赖未锁定版本（无版本号）: ' + $matches[1]) -context 'config' -doc $false))
      }
    }
  }
  $ppFiles = @(Get-ItemsSafe $root | Where-Object { $_.Name -eq 'pyproject.toml' })
  foreach ($f in $ppFiles) {
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
        if ($op -eq '==' -or $op -eq '===') {
          [void]$cveCandidates.Add([pscustomobject]@{ eco = 'PyPI'; name = $pkg; version = $ver; file = $f.FullName; line = $i + 1 })
        } else {
          [void]$out.Add((New-Finding -id 'SC1' -severity 'LOW' -file $f.FullName -line ($i + 1) -text ("依赖未锁定版本: $pkg ($op$ver)") -context 'config' -doc $false))
        }
      }
    }
  }
  $pjFiles = @(Get-ItemsSafe $root | Where-Object { $_.Name -eq 'package.json' })
  foreach ($f in $pjFiles) {
    try { $obj = Get-Content -Raw -Encoding UTF8 -LiteralPath $f.FullName -ErrorAction Stop | ConvertFrom-Json } catch { continue }
    $lines = @(Get-Content -Encoding UTF8 -LiteralPath $f.FullName -ErrorAction SilentlyContinue)
    foreach ($sec in @('dependencies','devDependencies','peerDependencies','optionalDependencies')) {
      $dep = $obj.$sec
      if (-not $dep) { continue }
      foreach ($prop in $dep.PSObject.Properties) {
        $spec = [string]$prop.Value
        $pinned = ($spec -match '^\d') -and ($spec -notmatch '^[~^<>=]')
        $ln = 1
        for ($i = 0; $i -lt $lines.Count; $i++) {
          if ($lines[$i] -match ('"' + [regex]::Escape($prop.Name) + '"\s*:')) { $ln = $i + 1; break }
        }
        if ($pinned) {
          [void]$cveCandidates.Add([pscustomobject]@{ eco = 'npm'; name = $prop.Name; version = $spec.TrimStart('=', ' '); file = $f.FullName; line = $ln })
        } else {
          [void]$out.Add((New-Finding -id 'SC1' -severity 'LOW' -file $f.FullName -line $ln -text ("npm 依赖未锁定版本: $($prop.Name) ($spec)") -context 'config' -doc $false))
        }
      }
    }
  }
  return [pscustomobject]@{ Findings = $out; Cve = $cveCandidates }
}

function Get-PythonExe {
  $candidates = New-Object System.Collections.ArrayList
  if ($Python) { [void]$candidates.Add($Python) }
  foreach ($c in @('python', 'python3')) {
    $g = Get-Command $c -ErrorAction SilentlyContinue
    if ($g) { [void]$candidates.Add($g.Source) }
  }
  $bundled = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
  [void]$candidates.Add($bundled)
  foreach ($c in @($candidates | Select-Object -Unique)) {
    if (-not (Test-Path -LiteralPath $c)) { continue }
    & $c -c 'pass' 2>$null
    if ($LASTEXITCODE -eq 0) { return $c }
  }
  return $null
}

function Invoke-AstCheck {
  param([string[]]$pyFiles, [System.Collections.ArrayList]$errors)
  $out = New-Object System.Collections.ArrayList
  $py = Get-PythonExe
  if (-not $py) {
    [void]$errors.Add('未找到 Python，AST 分析已跳过（仅正则扫描）')
    return $out
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
            [void]$out.Add((New-Finding -id $fd.id -severity $fd.sev -file $fd.file -line $fd.line -text $fd.text -context 'code' -doc $false))
          }
          foreach ($sk in @($obj.skips)) {
            if ($sk.file) {
              [void]$errors.Add(('AST 跳过 ' + $sk.file + ':' + $sk.line + ' ' + $sk.reason))
            }
          }
        } catch {
          [void]$errors.Add('AST 输出解析失败（退出码 ' + $pyCode + '）: ' + $_.Exception.Message)
        }
      } elseif ($pyCode -ne 0) {
        [void]$errors.Add('AST 分析器异常退出（退出码 ' + $pyCode + '，无输出，发现可能不完整）')
      }
    }
  } catch {
    [void]$errors.Add('AST 分析失败: ' + $_.Exception.Message)
  } finally {
    $ErrorActionPreference = $prevEap
  }
  return $out
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
        [void]$out.Add((New-Finding -id 'RP' -severity 'MED' -file $mf.FullName -line 0 -text ('manifest 自上次扫描发生变化（rug-pull 风险）: ' + $rel) -context 'config' -doc $false))
      }
    } else {
      [void]$out.Add((New-Finding -id 'RP' -severity 'LOW' -file $mf.FullName -line 0 -text ('新增 manifest 文件（未在基线中）: ' + $rel) -context 'config' -doc $false))
    }
  }
  return $out
}

function Get-GitHistoryFindings {
  param([string]$root, [System.Collections.ArrayList]$errors)
  $out = New-Object System.Collections.ArrayList
  if (-not $GitHistory) { return $out }
  $git = Get-Command git -ErrorAction SilentlyContinue
  if (-not $git) {
    $bundled = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\native\git\cmd\git.exe'
    if (Test-Path -LiteralPath $bundled) { $git = [pscustomobject]@{ Source = $bundled } }
  }
  if (-not $git) { [void]$errors.Add('未找到 git，git 历史扫描已跳过'); return $out }
  if (-not (Test-Path -LiteralPath (Join-Path $root '.git'))) { return $out }
  $prevEap = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    $lines = & $git.Source -C $root log --all -p -n $GitDepth 2>$null
    $secRe = 'sk-[A-Za-z0-9_\-]{20,}|ghp_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|-----BEGIN[^-]+PRIVATE\s+KEY-----|xox[baprs]-[A-Za-z0-9\-]{20,}'
    $seenSecret = @{}
    foreach ($line in $lines) {
      foreach ($m in [regex]::Matches($line, $secRe)) {
        $key = $m.Value
        if ($seenSecret.ContainsKey($key)) { continue }
        $seenSecret[$key] = $true
        [void]$out.Add((New-Finding -id 'CRED' -severity 'HIGH' -file (Join-Path $root '.git 历史') -line 0 -text ('git 历史含疑似密钥: ' + (Get-MaskedText $m.Value)) -context 'data' -doc $false))
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
      & powershell -NoProfile -ExecutionPolicy Bypass -File $jobArgs[0] @($jobArgs[1..($jobArgs.Count - 1)])
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
            severityCounts = $r.severityCounts; topCategories = @($r.topCategories); topFindings = @($r.topFindings)
          })
        } catch {
          [void]$results.Add([pscustomobject]@{ path = $d.target; root = $d.target; score = 0; severity = 'LOW'; recommendation = '扫描失败'; hasExecutable = $false; findings = @(); suppressed = @(); dependencies = @(); skipped = @(); errors = @('并行任务输出解析失败: ' + $_.Exception.Message) })
        }
      } else {
        [void]$results.Add([pscustomobject]@{ path = $d.target; root = $d.target; score = 0; severity = 'LOW'; recommendation = '扫描失败'; hasExecutable = $false; findings = @(); suppressed = @(); dependencies = @(); skipped = @(); errors = @('并行任务无输出（可能启动失败）') })
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
          [void]$out.Add((New-Finding -id 'SC4' -severity 'HIGH' -file $c.file -line $c.line -text ("已知漏洞依赖: $($c.name)==$($c.version) → $ids") -context 'config' -doc $false))
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
  $result = [ordered]@{
    path = $displayPath; root = $scanPath; score = 0; severity = 'LOW'; recommendation = '';
    hasExecutable = $false; findings = @(); suppressed = @(); dependencies = @(); skipped = @(); errors = @()
  }
  $findings = New-Object System.Collections.ArrayList
  $suppressed = New-Object System.Collections.ArrayList
  $skipped = New-Object System.Collections.ArrayList
  $errors = New-Object System.Collections.ArrayList
  $self = ((Split-Path $scanPath -Leaf) -eq $skillName)
  $root = $scanPath
  $allFiles = @()
  $hasExec = $false
  $cveCandidates = New-Object System.Collections.ArrayList
  $baselineFp = @{}
  if ($global:baselineFp) { $baselineFp = $global:baselineFp }

  $item = Get-Item -Force -LiteralPath $scanPath -ErrorAction Stop
  if ($item.PSIsContainer) {
    $allFiles = @(Get-ItemsSafe $root | Where-Object { $_.FullName -notmatch '\\\.git\\' })
  } else {
    $allFiles = @($item)
    $root = Split-Path $item.FullName -Parent
  }
  $result.root = $root

  # 分类：可扫描文本 vs 跳过清单
  $scanFiles = New-Object System.Collections.ArrayList
  foreach ($f in $allFiles) {
    if ($f.Name -like '.skillspector-baseline*' -or $f.Name -in @('.DS_Store', 'Thumbs.db')) { continue }
    if ($f.FullName -match '\\\.git\\') { continue }
    if ($skipExt -contains $f.Extension.ToLower()) {
      [void]$skipped.Add([pscustomobject]@{ file = $f.FullName; reason = '二进制/无法文本分析' })
      continue
    }
    if ($f.Length -gt $MaxFileBytes) {
      [void]$skipped.Add([pscustomobject]@{ file = $f.FullName; reason = ('超过单文件分析上限 ' + [Math]::Round($MaxFileBytes / 1MB, 1) + 'MB') })
      continue
    }
    [void]$scanFiles.Add($f)
  }

  # 逐文件单遍扫描
  foreach ($f in $scanFiles) {
    $content = Read-TextFile $f.FullName
    if (-not $content) { continue }
    $context = Get-ContextForFile $f $root
    if ($context -eq 'code') { $hasExec = $true }
    $isDoc = ($context -eq 'doc') -or $self
    $fenceSet = @{}
    $lines = $content.Text -split "`n"
    if ($context -eq 'doc') { $fenceSet = Get-FenceLines $lines }
    for ($li = 0; $li -lt $lines.Count; $li++) {
      $line = $lines[$li]
      foreach ($p in $linePatterns) {
        if ($f.Name -like '.env*' -and $p.id -in @('E2', 'CRED')) { continue }
        foreach ($m in [regex]::Matches($line, $p.re, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
          $ln = $li + 1
          $doc = $isDoc -or $fenceSet.ContainsKey($ln)
          if ($doc -and $f.Name -eq 'SKILL.md' -and $p.id -in $instructionIds -and -not $fenceSet.ContainsKey($ln)) {
            # 技能自身 SKILL.md 里的指令类命中（提示注入/反拒答/记忆投毒等）是真实信号，
            # 不按文档语境排除；扫描器自扫仍按 selfdoc 排除
            $doc = $self
          }
          $text = $line.Trim()
          if ($text.Length -gt 160) { $text = $text.Substring(0, 160) + '…' }
          $score = if ($p.PSObject.Properties['score']) { [bool]$p.score } else { $true }
          [void]$findings.Add((New-Finding -id $p.id -severity $p.sev -file $f.FullName -line $ln -text $text -context $context -doc $doc -score $score))
        }
      }
    }
    foreach ($p in $multiPatterns) {
      foreach ($m in [regex]::Matches($content.Text, $p.re, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
        $ln = Get-LineNumber $content.Text $m.Index
        $t = $m.Value -replace '\s+', ' '
        if ($t.Length -gt 160) { $t = $t.Substring(0, 160) + '…' }
        [void]$findings.Add((New-Finding -id $p.id -severity $p.sev -file $f.FullName -line $ln -text ('多行特征: ' + $t) -context $context -doc ($isDoc -or $fenceSet.ContainsKey($ln)) ))
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
  $depResult = Get-DependencyFindings $root
  foreach ($df in @($depResult.Findings)) { [void]$findings.Add($df) }
  $result.dependencies = @($depResult.Findings)
  foreach ($c in @($depResult.Cve)) { [void]$cveCandidates.Add($c) }

  # Python AST（发现 .py 文件且 Python 可用时自动执行）
  $codeFiles = @($scanFiles | Where-Object { $_.Extension.ToLower() -in @('.py', '.js', '.mjs', '.cjs') } | Select-Object -ExpandProperty FullName)
  if (-not $NoAst -and $codeFiles.Count -gt 0) {
    foreach ($af in @(Invoke-AstCheck -pyFiles $codeFiles -errors $errors)) { [void]$findings.Add($af) }
  }

  # OSV 已知漏洞查询
  foreach ($of in @(Invoke-OsvCheck -cveCandidates $cveCandidates -errors $errors)) { [void]$findings.Add($of) }

  # manifest 变化检测（需基线）
  foreach ($mf2 in @(Get-ManifestChangeFindings $root)) { [void]$findings.Add($mf2) }

  # git 历史敏感信息（可选）
  foreach ($gf in @(Get-GitHistoryFindings $root $errors)) { [void]$findings.Add($gf) }

  # 去重（id + 文件 + 行）
  $seen = @{}
  $unique = New-Object System.Collections.ArrayList
  foreach ($f in $findings) {
    $key = $f.id + '|' + $f.file + '|' + $f.line
    if ($seen.ContainsKey($key)) { continue }
    $seen[$key] = $true
    [void]$unique.Add($f)
  }
  $findings = $unique

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
  $result.findings = @($findings)
  $result.suppressed = @($suppressed)
  $result.skipped = @($skipped)
  $result.errors = @($errors)
  $result.rules = [pscustomobject]@{ version = $rulesMeta.version; updated = $rulesMeta.updated; source = $rulesMeta.source }
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
        return [ordered]@{ path = $target; root = $target; score = 0; severity = 'LOW'; recommendation = '扫描失败'; hasExecutable = $false; findings = @(); suppressed = @(); dependencies = @(); skipped = @(); errors = @($errors) }
      }
      $scanPath = $tempDir
    } catch {
      return [ordered]@{ path = $target; root = $target; score = 0; severity = 'LOW'; recommendation = '扫描失败'; hasExecutable = $false; findings = @(); suppressed = @(); dependencies = @(); skipped = @(); errors = @($errors) }
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

# ---------- 主流程 ----------
# 规则维护命令优先处理（不需要扫描目标）
if ($UpdateRules) {
  try {
    Update-RulesFromSource $UpdateRules
    [void](Get-LoadedRules)
  } catch {
    [Console]::Error.WriteLine('错误: ' + $_.Exception.Message)
    exit 2
  }
  exit 0
}
if ($ShowRules) {
  Show-RulesInfo
  exit 0
}
if ($ExportRules) {
  $exp = [ordered]@{
    version = $rulesMeta.version
    updated = (Get-Date -Format 'yyyy-MM-dd')
    source  = $rulesMeta.source
    linePatterns = @($linePatterns | ForEach-Object { [ordered]@{ id = $_.id; severity = $_.sev; regex = $_.re; score = if ($_.PSObject.Properties['score']) { [bool]$_.score } else { $true }; owasp = if ($_.PSObject.Properties['owasp']) { [string]$_.owasp } else { '' } } })
    multiPatterns = @($multiPatterns | ForEach-Object { [ordered]@{ id = $_.id; severity = $_.sev; regex = $_.re; owasp = if ($_.PSObject.Properties['owasp']) { [string]$_.owasp } else { '' } } })
    descMap = $descMap
  }
  $dir = Split-Path $ExportRules -Parent
  if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
  [System.IO.File]::WriteAllText($ExportRules, ($exp | ConvertTo-Json -Depth 5), (New-Object System.Text.UTF8Encoding($false)))
  Write-Output ('规则已导出: ' + (Resolve-Path -LiteralPath $ExportRules).Path)
  exit 0
}
if ($RuleId) {
  if (-not $Regex) {
    [Console]::Error.WriteLine('错误: 收录规则需要同时提供 -RuleId 和 -Regex')
    exit 2
  }
  try {
    Add-RuleEntry
  } catch {
    [Console]::Error.WriteLine('错误: ' + $_.Exception.Message)
    exit 2
  }
  exit 0
}

try {
  $targets = Get-Targets
} catch {
  [Console]::Error.WriteLine('错误: ' + $_.Exception.Message)
  exit 2
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
foreach ($r in $reports) {
  [void]$outLines.Add('==== 目标: ' + $r.path + ' ====')
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
    foreach ($s in $r.skipped) { [void]$outLines.Add(('[SKIP] ' + $s.file + ': ' + $s.reason)) }
    foreach ($e in $r.errors) { [void]$outLines.Add(('[ERR] ' + $e)) }
    [void]$outLines.Add(('==== 小结: score={0} / {1}（{2}）| 有效 {3} | 文档语境 {4} | 基线抑制 {5} | 跳过 {6} | 错误 {7} ====' -f `
      $r.score, $r.severity, $r.recommendation, $eff.Count, $docCount, $suppCount, $r.skipped.Count, $r.errors.Count))
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
  foreach ($r in @($reports | Sort-Object -Property { $_.score } -Descending)) {
    $eff = @($r.findings | Where-Object { -not $_.doc -and -not ($_.PSObject.Properties['suppressed'] -and $_.suppressed) }).Count
    $sc = $r.severityCounts
    $scC = if ($sc) { [int]$sc.CRITICAL } else { 0 }
    $scH = if ($sc) { [int]$sc.HIGH } else { 0 }
    $scM = if ($sc) { [int]$sc.MEDIUM } else { 0 }
    $scL = if ($sc) { [int]$sc.LOW } else { 0 }
    $top1 = if ($r.topCategories -and @($r.topCategories).Count -gt 0) { @($r.topCategories)[0] } else { '-' }
    [void]$outLines.Add(('{0} | {1} | {2} | {3} | 有效 {4} | C{5}/H{6}/M{7}/L{8} | 重点 {9} | 跳过 {10}' -f `
      $r.path, $r.score, $r.severity, $r.recommendation, $eff, $scC, $scH, $scM, $scL, $top1, $r.skipped.Count))
  }
}
[void]$outLines.Add('==== 扫描完成 ====')

if ($Json) {
  $jsonObj = [ordered]@{
    version = 1
    generated = (Get-Date -Format o)
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
