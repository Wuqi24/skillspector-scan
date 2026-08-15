# Reason Codes Contract

> 状态：Phase 4B 冻结
> 版本：1.0
> 角色：`reason_code` 唯一来源；新增/修改必须走契约变更（版本递增 + migration 记录 + 兼容测试），禁止运行时收录。

## 规则

- `reason_code` 独立于 `status`：`status=degraded` 可配 `reason_code=external_missing`。
- 仅非 `executed` 的 inspection 条目需要 `reason_code`；`executed` 条目为 `null`。
- 枚举值不得在业务逻辑中散落硬编码；scan.ps1 内嵌冻结常量数组与本文档保持一致（T72 校验）。

## 冻结枚举

| reason_code | 含义 |
|---|---|
| `binary_asset` | 已知静态资产（图片/字体/媒体），跳过但不影响完整性 |
| `binary_content` | 二进制内容无法文本分析 |
| `oversized` | 超过单文件分析上限 |
| `permission_denied` | 目录/文件无读取权限 |
| `unsupported_encoding` | 编码识别失败（所有回退失败） |
| `external_missing` | 可选外部依赖缺失（python / aguara / skill-scanner / OSV 等） |
| `not_applicable` | 引擎对当前目标不适用（如无对应文件类型） |
| `no_files` | 目标无可分析文件 |
| `parse_error` | 解析失败（AST 等） |
| `dependency_unresolved` | 依赖解析未完成/不可用 |
| `disabled_by_config` | 被配置/参数显式禁用（-NoAst / -NoExt 等） |
| `unknown` | 无法归因的兜底值 |

## 变更流程

1. 修改本文档（版本递增 + 变更说明）
2. 同步 schema-v2.json 的 `reason_code` enum
3. 同步 scan.ps1 内嵌冻结数组
4. 跑全量回归（T72 契约同步校验）
