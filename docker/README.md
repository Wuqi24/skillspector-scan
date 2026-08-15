# skillspector-scan 容器使用

在 Docker 中直接扫描本地技能，无需安装 PowerShell/Python/git。扫描为只读挂载，容器不写宿主任何文件，`--rm` 退出即销毁。

## 构建镜像

```powershell
docker build -t skillspector-scan -f docker/Dockerfile .
```

## 扫描单个技能

```powershell
docker run --rm -v "C:\技能所在路径\技能名:/skills/技能名:ro" skillspector-scan -Path /skills/技能名
```

挂载目录名应保持技能名（与 `SKILL.md` 的 name 一致），避免目录命名假阳性。

## 批量 / 并行

```powershell
# 批量扫描宿主上的技能文件夹（每个子目录一个目标）
docker run --rm -v "C:\技能父目录:/skills:ro" skillspector-scan -Dir /skills

# 并行（容器内自动用 pwsh 跑 worker，Linux 下无 powershell 也可用）
docker run --rm -v "C:\技能父目录:/skills:ro" skillspector-scan -Dir /skills -Parallel
```

## 验证镜像

仓库内 `docker/fixtures/evil-test` 是恶意夹具（subprocess + base64 载荷），构建后应检出 CRITICAL：

```powershell
docker run --rm -v "C:\<仓库>\skillspector-scan\docker\fixtures\evil-test:/skills/evil-test:ro" skillspector-scan -Path /skills/evil-test
```

## 注意事项

- 镜像基于 `mcr.microsoft.com/powershell:latest`，内含 python3 与 git，Python AST / git 历史检查可用。
- 容器内无 `USERPROFILE`，扫描器已做空值保护，Codex 内置运行时回退自动跳过。
- 只读挂载扫描，容器不写入技能目录。
