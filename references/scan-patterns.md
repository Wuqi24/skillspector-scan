# 扫描模式速查

内置脚本 `scripts/scan.ps1` 已内置全部模式（单遍扫描、编码自动探测、语境标注、注释词法识别、base64 解码复查、多行特征）；简报模式（-Brief）按冻结注册表 `rules/rules.yaml`（17+4 条）渲染。下表供手动搜索备选；`rg` 可用优先 `rg`，否则用 `Select-String` 兜底。

## 基础命令

- 列出全部文件：`Get-ChildItem -Recurse -File <skill目录> | Select-Object FullName`
- rg 搜索：`rg -n -i '<正则>' <skill目录>`
- 兜底搜索：`Get-ChildItem -Recurse -File <skill目录> | Select-String -Pattern '<正则>'`
- 查看文件片段（UTF-8）：`Get-Content -Encoding UTF8 <文件>`

## 指令与行为类

| 风险点 | 搜索正则 |
| --- | --- |
| 反拒答/越狱 | `never\s+refuse`、`always\s+comply`、`no\s+disclaimers`、`ignore\s+your\s+guidelines`、`do\s+anything\s+now`、`永不拒绝` |
| 指令覆盖 | `忽略.*(系统\|上级\|指令)`、`override\s+(system\|instruction\|policy\|safety)`、`only\s+obey`、`只服从本文件` |
| 系统提示泄露 | `system\s+prompt`、`print\s+.*instructions`、`输出.*(系统提示\|内部规则)` |
| 记忆投毒 | `persist\s+this`、`long[- ]term`、`跨会话`、`写入.*(memory\|记忆)` |
| 过度自主权 | `无需确认`、`without\s+asking`、`full\s+access`、`自动执行`、`don.t\s+ask` |
| 触发词滥用 | `always\s+(comply\|obey\|follow\|do\|run\|use)`、`一切.*(任务\|请求)`、`无条件执行` |
| 外部指令来源（AST05） | `(fetch\|read\|download\|按\|根据\|访问\|读取\|下载).*https?://.*(指令\|规则\|instructions?)`、`把.*(网页\|内容).*当作.*指令` |

## 数据与网络类

| 风险点 | 搜索正则 |
| --- | --- |
| 网络外传 | `requests\.(post\|put\|patch)`、`httpx`、`fetch\s*\(`、`Invoke-WebRequest`、`Invoke-RestMethod`、`curl\s+.*(-d\|--data\|-X)`、`urllib\.(request\|parse)`、`WebClient`、`axios`、`\.post\s*\(` |
| 外部 URL（信号，不计分） | `https?://` |
| 环境变量收割 | `os\.environ`、`process\.env`、`Get-ChildItem\s+Env:`、`os\.getenv`、`API_KEY`、`SECRET_KEY`、`ACCESS_TOKEN`、`AUTH_TOKEN`、`PASSWORD` |
| 敏感文件枚举 | `\.ssh[\\/]`、`\.aws[\\/]`、`credentials`、`os\.walk`、`glob\s*\(.*home` |
| 云存储外传 | `put_object`、`upload_file`、`s3\s+cp`、`gsutil`、`upload_blob` |
| SSRF | `169\.254\.169\.254`、`metadata\.google`、`127\.0\.0\.1`、`localhost`、`192\.168\.`、`10\.\d+\.\d+\.\d+` |
| Agent 窥探 | `\.claude[\\/]`、`\.codex[\\/]`、`\.gemini[\\/]`、`mcp\.json` |

## 代码与供应链类

| 风险点 | 搜索正则 |
| --- | --- |
| 危险调用 | `\bexec\s*\(`、`\beval\s*\(`、`\bcompile\s*\(`、`__import__\s*\(`、`os\.system\s*\(`、`subprocess\.`、`Invoke-Expression`、`child_process`、`execSync`、`new\s+Function\s*\(`、`Start-Process` |
| 动态 getattr | `getattr\s*\([^)]*,\s*[^"']` |
| 远程脚本 | `curl\s+.*\|\s*(ba)?sh`、`wget\s+.*\|\s*(ba)?sh`、`irm\s+.*\|\s*iex`、`DownloadString`、`DownloadFile` |
| 混淆执行 | `b64decode\s*\(`、`Convert\.FromBase64String`、`-enc\s+[A-Za-z0-9+/=]{16,}` |
| 持久化/自启 | `crontab`、`schtasks`、`Startup[\\/]`、`launchd`、`systemd`、`\.bashrc`、`\.zshrc`、`HKCU:` |
| 提权 | `sudo\s`、`runas\s`、`--no-sandbox`、`-ExecutionPolicy\s+Bypass`、`requireAdministrator` |
| 工具滥用 | `shell\s*=\s*True`、`--force`、`--yes`、`privileged:\s*true`、`hostPath` |
| 删除操作 | `rm\s+-rf`、`Remove-Item\s+.*-Recurse`、`shutil\.rmtree`、`os\.unlink` |
| 真实凭据（输出自动脱敏） | `sk-[A-Za-z0-9_\-]{20,}`、`ghp_[A-Za-z0-9]{30,}`、`AKIA[0-9A-Z]{16}`、`BEGIN.*PRIVATE\s+KEY`、`xox[baprs]-` |

## 恶意特征（多行/整文件）

| 风险点 | 特征 |
| --- | --- |
| 反弹 shell | `(?s)bash\s+-i\s+>&?\s*/dev/tcp/` |
| 脚本一行流载荷 | `(?s)(python\|perl\|ruby)\s+-c\s+['"][^'"]{0,300}(socket\|pty\|exec\|base64)` |
| 编码 PowerShell | `(?s)powershell[^\r\n]{0,150}\s+(-enc\|-e)\s+[A-Za-z0-9+/=]{20,}` |
| 管道远程脚本 | `(?s)curl\s+[^\r\n]{0,200}\s*\|\s*(ba)?sh`、`(?s)wget\s+[^\r\n]{0,200}\s*\|\s*(ba)?sh` |
| base64 载荷 | 长度 ≥64 的 base64 串，解码后含 `exec(`/`eval(`/`subprocess`/`powershell`/`curl` 等关键词 |
| Webshell | `<\?php[^\r\n]*(eval\|assert\|system)\s*\(`、`eval\s*\(\s*\S*_POST`、`cmd\s+/c` |
| 矿机 | `stratum`、`xmrig`、`minergate`、`nicehash` |
| 攻击工具 | `metasploit`、`sqlmap`、`nuclei\s+-t`、`nikto`、`hydra`、`masscan` |

## 混淆与隐藏内容

| 风险点 | 搜索正则 |
| --- | --- |
| base64/hex | `b64decode\s*\(`、`atob\s*\(`、`btoa\s*\(`、`\\x[0-9a-f]{2}`、`\\u[0-9a-f]{4}` |
| 零宽/不可见字符 | `\u200b`、`\u200c`、`\u200d`、`\ufeff`、`\u202e`（RTL 覆盖） |

## 结构化检查（脚本自动完成）

- 依赖锁定：`requirements*.txt` / `Pipfile` / `environment.yml` / `pyproject.toml` / `package.json`，未锁定版本输出 SC1；已锁定版本在 `-CheckCVE` 时联网查 OSV.dev（SC4）
- frontmatter：所有 `SKILL.md` 的 name/description 完整性与目录名一致性（MD）
- `.env`：真实凭据变量名（值隐藏，CRED）
- 符号链接/联接越界（SYMLINK）
- 注释词法识别：Python `#`、JS/TS `//` 与 `/* */`、PowerShell/Shell/Ruby `#`、HTML `<!-- -->`，字符串内不算注释（lexer.py）
- Python AST：`scripts/ast_check.py` 解析 .py 文件，输出 DC1-DC8 危险调用、E1 网络信号、TT3/TT5 轻量污点
- JS 行为启发式：`scripts/ast_check.py` 对 .js/.mjs/.cjs 做轻量词法分析，输出 DC2/DC4/DC8（eval/exec/子进程）、E1（fetch/axios/http）、TT3/TT5（外部输入流入执行/网络）
- git 历史：`-GitHistory` 扫描最近 N 次提交补丁中的疑似密钥（输出自动脱敏）
- manifest 变化：配合基线使用时，SKILL.md / mcp.json / agents 配置哈希变化输出 RP（rug-pull）
- 离线依赖分析（简报模式）：非白名单源（DEP_SOURCE）、疑似拼写相似包（DEP_TYPOSQUAT）、安装脚本钩子（DEP_HOOK）、未声明依赖（DEP_UNDECLARED）、直接依赖数超阈值（DEP_COUNT）

## 判断要点

- 有网络调用不等于危险：看目标域名是否与功能相关、是否上传本地数据
- 有删除命令不等于危险：看路径是否受限（如只清理临时目录）
- 混淆内容（base64、hex、转义）必须解码后检查，不能只看表面
- 技能目录里的 `.env` 不应包含真实密钥；出现真实凭据属于严重问题
- 把用户输入拼进 shell 命令的地方要警惕命令注入
- 文档/示例语境（.md、Markdown 围栏代码块、扫描器自身）里的命中由脚本标记为“文档语境”，不计分；配置/代码语境仍需人工判断
- 上下文不明、置信度低时标“需人工确认”，不臆断
