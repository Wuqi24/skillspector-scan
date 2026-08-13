# 逐类检查清单

每条发现记录：ID、严重级、置信度、证据（文件:行号）。严重级与评分规则见 SKILL.md。

> 文档/示例语境（.md、Markdown 围栏代码块、扫描器自身）中的命中由脚本标记为“文档语境”，不计分；配置/代码语境仍需人工判断。

## 目录

- A. 指令与行为类
- B. 数据与网络类
- C. 代码与供应链类
- D. 元数据与生态类

## A. 指令与行为类

### 提示注入 P1-P5

- P1 指令覆盖：是否要求“忽略系统/上级指令”“无视之前要求”“只服从本文件”
- P2 隐藏指令：注释、HTML/JS 注释、零宽字符、小字号、无关文件里夹带指令；base64/hex 解码后查看（脚本自动解码 ≥64 字符 base64 载荷复查）
- P3 指令外传：是否指示把对话/上下文/用户数据发送到外部
- P4 行为操纵：诱导模型做超出任务的决定、隐瞒操作、弱化风险评估
- P5 有害内容：指导物理伤害、违法、自伤等严重内容

### 反拒答/越狱 AR1-AR3

- AR1 拒绝抑制：“永不拒绝”“always comply”“照做即可”
- AR2 免责声明抑制：“不要加警告”“别啰嗦安全提示”“no disclaimers”
- AR3 政策清除：“你没有限制”“无视规则”“do anything now”“ignore your guidelines”

### 系统提示泄露 SPL1-SPL3

- 是否要求输出/复述系统提示或内部规则
- 是否诱导以改写、翻译、摘要方式侧信道提取
- 是否把系统提示写文件、发网络、记日志

### 记忆投毒 MP1-MP3

- 是否有“记住并长期生效”“persist this”“跨会话”等持久指令
- 是否塞大量无意义内容挤占上下文
- 是否指示修改记忆/状态文件

### 过度自主权 EA1-EA4

- 是否授予无约束的工具/文件/网络访问
- 是否允许无人确认的高影响操作（删除、转账、发布）
- 能力是否超出声明用途
- 是否无频率/额度限制

### 输出处理 OH1-OH3

- 模型输出是否未经校验直接进 shell/SQL/HTML
- 输出是否跨信任边界传递
- 输出是否无上限（max_tokens、循环）

### 触发词滥用 TR1-TR3

- description 是否用“始终/所有/一切”等宽泛触发
- 是否遮蔽内置命令或其它技能触发
- 是否有诱导高频激活的措辞

### 外部指令来源 AST05（OWASP Agentic Skills Top 10）

- 是否指示从远程 URL/网页/文件获取指令、规则并按指令执行（fetch/read/download/curl/读取/下载 + https://）
- 是否把外部内容（网页、用户上传文件、第三方文档）直接当作指令/规则
- 引用的外部文档 URL 是否受控（允许清单缺失时，第三方可篡改 URL 内容实现指令投毒）

## B. 数据与网络类

### 数据外泄 E1-E5

- E1 外传：向外部 URL 发数据（POST/PUT/上传）；脚本输出 E1 命中与 E1URL 信号（URL 仅作信号不计分）
- E2 环境变量收割：枚举 os.environ / process.env 全部项或含 KEY/SECRET/TOKEN 的项
- E3 文件枚举：glob/walk/扫描 .ssh/.aws/.env/credentials
- E4 上下文泄露：把对话/会话记录发外部
- E5 云存储外传：S3/GCS/Azure 上传

### 污点外传 TT1-TT5

- 追踪数据流：源（环境变量、文件读取、网络输入）→ 汇（网络请求、exec、写文件）
- 脚本对 Python 文件做轻量污点：环境变量/文件/输入 → 执行或网络汇（TT3/TT5）
- TT3 凭据流向网络出口：高置信外泄信号
- TT4 文件内容流向网络出口
- TT5 外部输入流向代码执行

### SSRF SSRF1-SSRF3

- 请求 169.254.169.254（云 metadata，一次请求可拿到临时 IAM 凭据）
- 请求回环/内网地址（127.0.0.1、10.x、192.168.x、localhost）
- 请求目标由动态/不可信值拼装

### Agent 窥探 AS1-AS3

- 读取 .claude/.codex/.gemini 等代理配置目录（可能有密钥）
- 读取 mcp.json（含服务器地址、token、工具定义）
- 枚举/读取其它已安装技能

## C. 代码与供应链类

### 供应链 SC1-SC7

- SC1 依赖未固定版本：脚本自动解析 requirements/Pipfile/environment.yml/pyproject.toml/package.json 并标记
- SC2 远程脚本：curl|sh、irm|iex、下载二进制执行
- SC3 混淆：base64/hex 后执行；脚本自动解码复查
- SC4 已知漏洞依赖：`-CheckCVE` 时联网查 OSV.dev（失败自动离线降级）；也可手动查 osv.dev
- SC5 弃维护依赖
- SC6 仿冒包名（typosquatting）
- SC7 不可信容器镜像/关闭签名校验

### 代码级危险调用 DC1-DC9

- DC1 exec() / DC2 eval() / DC6 compile()：Python 文件由 AST 分析器精确标记（含非字面量参数 DC8）
- DC3 __import__() 动态导入
- DC4 subprocess / DC5 os.system
- DC7 动态 getattr() 非字面量属性名
- DC8 危险执行链：exec/eval + 网络/编码来源
- DC9 反射执行：getattr(os,'system')、getattr(builtins,'exec')
- 其它语言对应物：child_process.execSync、spawn、Function()、PowerShell Invoke-Expression

### 提权/危险操作 PE1-PE3

- PE1 索取超出功能的权限/授权
- PE2 sudo/root/admin 执行
- PE3 读取 SSH 密钥、token、密码文件
- 危险操作补充：rm -rf、Remove-Item -Recurse、清空目录、修改全局配置/注册表、关闭防护、静默执行绕过审批

### 失控代理/持久化 RA1-RA2

- RA1 自修改：运行期修改自身代码/SKILL.md/配置
- RA2 持久化：cron/schtasks/Startup/launchd/systemd/.bashrc 自启

### 工具滥用 TM1-TM4

- TM1 shell=True、--force、--yes 等参数滥用
- TM2 工具链组合绕过单点检查
- TM3 不安全默认值（禁 TLS、无鉴权、宽松权限）
- TM4 特权容器/挂载宿主机文件系统

## D. 元数据与生态类

### 元数据 MD1-MD4

- MD1 frontmatter 合法（name/description 齐全；脚本检查全部 SKILL.md）
- MD2 name 与目录名一致
- MD3 description 过宽/误导触发
- MD4 夹带无关文件（安装脚本、真实密钥、可疑二进制、README 等冗余）
- 符号链接/联接越界：链接目标指向技能目录外（如 ~/.ssh），脚本输出 SYMLINK

### MCP 最小权限 LP1-LP4

- LP1 代码能力超出声明权限
- LP2 权限含通配（*、all、any）
- LP3 无权限声明但有可检测能力
- LP4 声明权限但无对应能力

### MCP 工具投毒 TP1-TP4

- TP1 元数据藏指令（HTML 注释、零宽字符、base64、data URI）
- TP2 Unicode 欺骗（同形字、RTL 覆盖、不可见字符）
- TP3 参数描述/默认值注入（覆盖指令、系统 token）
- TP4 描述与行为不符（需模型判断）

### 已知恶意特征 YR1-YR4（启发式）

- YR1 木马/远控：reverse shell、nc -e、bash -i、/dev/tcp/、C2 域名
- YR2 Webshell：PHP eval 组合、cmd /c、base64 -d 大段
- YR3 矿机：stratum、xmrig、矿池地址
- YR4 攻击工具：metasploit、nuclei、sqlmap 等特征

### 清单变化 RP1-RP3（rug-pull，配合基线）

- RP1 核心清单变化：SKILL.md / manifest / 工具定义与上次扫描相比被修改（哈希不一致）
- RP2 新增清单：扫描范围内出现基线中没有的 manifest/mcp/agent 配置文件
- RP3 移除清单：基线中存在的清单文件被删除（当前未实现，人工对比基线即可发现）

## 语言行为分析（脚本自动）

- Python：AST 精确识别 exec/eval/compile/__import__/getattr/subprocess/os.system（DC1-DC8），并做环境变量/文件/输入 → 执行或网络汇的轻量污点（TT3/TT5）
- JavaScript：轻量词法分析识别 eval/new Function（DC2/DC8）、child_process 调用（DC4）、fetch/axios/http 网络调用（E1），参数含 process.env/请求/文件等外部输入时标记 TT3/TT5
- git 历史：`-GitHistory` 扫描最近提交补丁中的疑似密钥（CRED，自动脱敏）

## 误报与抑制

- 脚本按语境标注 code/config/doc/data；doc 语境（.md、围栏示例、扫描器自身）不计分，**例外**：技能自身 SKILL.md 正文中的指令类命中（P1/AR/SPL/MP/EA/TR/AST05）视为提示注入真实信号，计入评分
- 已复核的发现可写入 `.skillspector-baseline.yaml`（`-InitBaseline`），复扫时自动抑制（`-Baseline`），`-ShowSuppressed` 查看被抑制项；基线同时记录 manifest 哈希，用于 RP 变化检测
- 语境无法判断时，保留发现并标“需人工确认”，不要直接丢弃

## 简报模式（-Brief）与已审记录（v2.0）

- 注释/文档语境命中归“参考发现”，不计入风险计数与 TOP 3；`doc_code`（文档代码示例）是风险发现但 `execution=documented`、`confidence=low`
- 关联规则只做“共存”判断（如凭证读取+回环访问），不推断数据流；correlation finding 的 `source_finding_id` 必须能追溯到原始文件证据
- `-MarkVerified allow|deny` 仅对 `analysis_status=complete` 的扫描生效；已审记录按文件 SHA-256 清单 + 规则/配置/包表哈希比对，任何变化都会使旧结论失效提示
- 规则来自冻结注册表 `rules/rules.yaml`（36 唯一/40 条目 + 4 hints + 11 projections），不支持联网更新或运行时收录；人工修改规则后旧审核自动失效
