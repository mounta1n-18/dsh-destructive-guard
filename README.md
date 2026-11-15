# @local/dsh-destructive-guard

版本 1.1.0。

给 DSH 的 shell 工具加一道“不可逆命令”护栏：命中即拒绝（或要求确认），并给出模型可读的理由。目标不是替代沙箱，而是让 `Remove-Item -Recurse -Force $home` 这类诺亚方舟式命令在**执行前**停下来。1.1.0 起也审 `write` / `edit` / `apply_patch` 的落点（会话日志、记忆、凭证、密钥、系统目录），并在 `approval policy = never` 时把 `ask` 级规则显式降级为 `deny`。

## 挂点

- `tools/pre-execute`：返回 `deny`（硬拦）或 `ask`（需要审批），模型能看到原因；
- `ctx.tools.guard`：单调守卫，兜住 `block` 级命令，后续监听器无法把它改回允许；
- 审查 `pwsh` / `bash` / `terminal` / `shell` / `cmd` 的 `command` 参数，以及 `write` / `edit` / `apply_patch` / `str_replace_editor` 的目标路径；
- 从 `sessions` + `approval` 服务读当前会话的有效策略（`overrideOf(session) ?? approval.config.policy ?? 'ask'`），据此决定 `ask` 是否还能弹确认；
- 不注册工具、不改提示词、不读写数据。

## 拦截范围

| 级别 | 规则 | 例子 |
| --- | --- | --- |
| block | `FS-HOME` | `Remove-Item -Recurse -Force $home`、`C:\Users\ROSE`、`~\Documents`、`C:\Users\ROSE\*`、多行 / `if`/`try` 块里的同款命令、`ls $home \| ri -Force`、`~/.ssh/id_ed25519` |
| block | `FS-ROOT` | `rm -rf /`、`rd /s /q C:\`、`del /s C:\*` |
| block | `FS-TRAVERSAL` | `...\Documents\..\Desktop`、`$home\..\` |
| block | `RECOVERY-INHIBIT` | `vssadmin delete shadows`、`wmic shadowcopy delete`、`wbadmin delete catalog`、`bcdedit recoveryenabled no`、`reagentc /disable` |
| block | `DISK-WIPE` | `format C:`、`diskpart clean`、`Clear-Disk`、`dd of=/dev/...`、`mkfs` |
| block | `DATA-WIPE` | `cipher /w`、`sdelete`（根/家目录） |
| block | `LOG-WIPE` | `wevtutil cl`、`auditpol /clear`、`fsutil usn deletejournal` |
| block | `REGISTRY-WIPE` | `reg delete HKLM/HKU/HKCR/HKCC` |
| block | `ACL-TAKEOVER` | `takeown /f C:\`、`icacls C:\ /reset`、对家目录做同样操作 |
| block | `SERVICE-ACCOUNT` | `sc delete`、`net user ... /delete` |
| block | `SECURITY-TAMPER` | `Set-MpPreference -Disable*`、`netsh advfirewall ... off`、`manage-bde -off` |
| block | `VM-DESTROY` | `wsl --unregister`（含 WSL 内 `rm -rf /mnt/c/Users/...`） |
| block | `BOOT-CONFIG` | `bcdedit`、`bootrec /fixmbr`、`reagentc /disable` |
| block | `FS-PERMISSIONS` / `FORK-BOMB` | `chmod -R 000 /`、`chown -R ... /`、fork bomb |
| block | `ENCODED-CMD` | `powershell -EncodedCommand ...` |
| block | `REMOTE-EXEC` / `LOLBAS` | `iwr ... \| iex`、`mshta http`、`regsvr32 /i:http` |
| block | `WRAPPED-DESTRUCTIVE` / `SCRIPT-DELETE` | `Start-Job { Remove-Item ... }`、`python -c "shutil.rmtree(...)"`、`node -e "fs.rmSync(...)"` |
| ask | `GIT-DESTRUCTIVE` | `git reset --hard`、`git clean -fdx`、`git push --force` |
| ask | `CONTAINER-PRUNE` / `CLUSTER-DELETE` / `INFRA-DESTROY` | `docker system prune -a`、`kubectl delete`、`terraform destroy` |
| ask | `DB-DESTRUCTIVE` | `DROP TABLE`、`TRUNCATE` |
| ask | `RECYCLE-BIN` / `POWER-STATE` | `Clear-RecycleBin`、`shutdown /r` |
| ask | `SYSTEM-COMPONENT` / `SCHEDULE-DELETE` | `wusa /uninstall`、`dism /remove-package`、`schtasks /delete` |
| ask | `FS-FIND-DELETE` / `FS-SHRED` / `FS-CWD` | `find . -delete`、`shred`、`rm -rf .` |
| block | `FS-PROTECTED` | `write`/`edit` 指向 `~/.dsh/sessions`、`~/.dsh/memory`、`~/.dsh/AGENTS.md`、`.credentials.yaml`、`.github-mcp-token`、`.mcd-mcp-token`、`.ssh`、`.aws`、`.gnupg`、`C:\Windows`、`Program Files`；`apply_patch` 的 `*** Update File:` 头同样检查 |

明确放行：`Remove-Item -Recurse -Force .\build`、`rm -rf node_modules`、`Remove-Item $env:TEMP\scratch`、家目录下的深层构建目录（如 `Documents\proj\build`）、`git status`、`pnpm test` 等；`write`/`edit` 写工作区、写 `~/.dsh/profiles/<name>/package.json`、写任意位置的 `AGENTS.md`（家目录根与 `.dsh` 下那两份除外）也放行——否则装插件、改提示词会先被自己拦下。

## approval policy = never 时

`ask` 级规则在官方 `danger-full-access` 预设（`never`）下不会弹确认，而是被 `@deepseek-ai/dsh-user-approval` 确定性拒绝，模型只看到失败、看不到原因。1.1.0 起本插件自己读策略：

- `policy = ask`（或读不到 approval 服务）：照旧返回 `{kind:'ask'}`，正常弹确认；
- `policy = never`：把 `ask` **显式降级为 `deny`**，reason 带命中规则名、原命令、以及「当前会话 approval policy = never，不会弹确认；要执行请把权限预设切回 ask 档」，并写一条 `logger.warn`；
- `block` 级规则不受策略影响，理由里也不会出现 policy 字样；
- 判定过程抛异常时仍 fail-open（放行），但会记 `logger.warn`。

没有“静默放行开关”：要执行被 ask 的操作，只能把权限预设切回 ask 档。

## 接口

| 路由 | 作用 |
| --- | --- |
| `GET /dsh-destructive-guard/status` | 版本、启用状态、规则清单 |
| `POST /dsh-destructive-guard/check` | body `{"command":"..."}` 或 `{"file_path":"...","tool":"write"}`，只跑纯判定、不执行命令，返回 `block/ask/allow` 与规则 id |

## 性能

判定是纯字符串正则，在每次工具调用前跑一次（pre-execute + 单调 guard，共两次）：实测典型命令约 **30–40 µs**（79 字节样本 20000 次均值 36 µs），长命令线性增长；比进程启动（几十到几百 ms）低三个数量级；不注册工具、不增加提示词 token、不做文件 IO。对模型延迟的影响可忽略。

## 局限（必须知道）

- 它**不是沙箱**：只拦命令字符串里看得见的模式。`[Environment]::GetFolderPath()` 拼接、运行时生成脚本、GUI 自动化（`computer_use` 往终端里打字）、自写二进制都能绕过。
- **文件工具只审落点、不审语义**：`write` / `edit` / `apply_patch` 的目标路径命中保护清单会拦，但把破坏性内容写进一个普通文件（例如 `C:\temp\x.ps1`）本身不拦；随后按路径执行时也看不见内容。`run_code` 里 `child_process` 删目录同样绕过。
- **不审脚本内容**：`powershell -File verify.ps1`、`python x.py`、`node x.js` 只按路径执行，脚本里写什么它看不见；先写脚本再执行是现成绕过路径。
- `-EncodedCommand` 一律拦，不做解码审查。
- 命令别名 / 函数覆盖（`function rm {}`）不在覆盖范围。
- `-WhatIf` 预览也会被拦（宁可误拦）。
- 仍应保持：测试用 `workspace-write` 沙箱、破坏性操作要审批、升级前备份 `.dsh/.claude/.doubao`。

## 运行测试

```powershell
cd "C:\DSH Plugin\dsh-destructive-guard"
node --test
```

`test/classify.test.mjs` 覆盖家目录、盘根、恢复/日志/注册表、编码命令、路径穿越、WSL 路径、包装器、多行与 `if`/`try` 块、变量污点、别名管道、敏感子目录、跨语句假管道与 `?` 回归、write/edit/apply_patch 落点、放行样本等；`test/hook.test.mjs` 用假 ctx 覆盖 `never` 降级、`ask` 不变、配置默认 `never`、读不到 approval 回退 `ask`、文件工具 deny。测试只调用纯函数与假对象，不执行任何命令，也不碰 `~/.dsh`。

## 对诺亚方舟事件的覆盖

| 当时发生的事 | 现在 |
| --- | --- |
| 22:36 `Remove-Item -Recurse -Force $home` | 拦（`FS-HOME`），多行 / 块内 / 变量中转的写法也拦 |
| 15:24 安装流程直接删 `~/.dsh`、`~/.claude` | **不覆盖**：不是 shell 命令，插件看不见 |
| 先写 `verify.ps1` 再 `powershell -File` 执行 | **不覆盖**：只认命令行，不读脚本内容 |

所以它是“降低再犯概率”的一道闸，不是复现免疫；配合审批模式与升级前备份才完整。

## 关闭

临时关闭：设置环境变量 `DSH_GUARD=off`（需要重启/重载插件）；或从 profile 的 `dsh.profile.bundles` 移除本 bundle。
