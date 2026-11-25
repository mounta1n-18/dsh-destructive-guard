# @local/dsh-destructive-guard

版本 1.2.0。

给 DSH 的 shell 工具加一道“不可逆命令”护栏：命中即拒绝（或要求确认），并给出模型可读的理由。目标不是替代沙箱，而是让 `Remove-Item -Recurse -Force $home` 这类诺亚方舟式命令在**执行前**停下来。1.1.0 起也审 `write` / `edit` / `apply_patch` 的落点（会话日志、记忆、凭证、密钥、系统目录），1.2.0 起连 `read` 读秘密文件也拦；并在 `approval policy = never` 时把 `ask` 级规则显式降级为 `deny`。

1.2.0 的核心变化是**从“命令里出现受保护路径”改为“删除动词的真实目标落在受保护路径上”**：删临时文件、删家目录深层构建产物、在项目目录里按管道清理都不再误拦（详见下文“v1.2.0：按目标判定”）。

## 挂点

- `tools/pre-execute`：返回 `deny`（硬拦）或 `ask`（需要审批），模型能看到原因；
- `ctx.tools.guard`：单调守卫，兜住 `block` 级命令，后续监听器无法把它改回允许；
- 审查 `pwsh` / `bash` / `terminal` / `shell` / `cmd` 的 `command` 参数，以及 `write` / `edit` / `apply_patch` / `str_replace_editor` 的目标路径；
- 从 `sessions` + `approval` 服务读当前会话的有效策略（`overrideOf(session) ?? approval.config.policy ?? 'ask'`），据此决定 `ask` 是否还能弹确认；
- 不注册工具、不改提示词、不读写数据。

## 拦截范围

| 级别 | 规则 | 例子 |
| --- | --- | --- |
| block | `FS-HOME` | `Remove-Item -Recurse -Force $home`、`C:\Users\ROSE`、`~\Documents`、`C:\Users\ROSE\*`、多行 / `if`/`try` 块里的同款命令、`ls $home \| ri -Force`、`~/.ssh/id_ed25519`、`~/.dsh/memory`；按**删除目标的深度**判定，`%TEMP%` 与家目录深层子路径放行 |
| block | `FS-ROOT` | `rm -rf /`、`rd /s /q C:\`、`del /s C:\*` |
| block | `FS-TRAVERSAL` | `...\Documents\..\Desktop`、`$home\..\` |
| block | `RECOVERY-INHIBIT` | `vssadmin delete shadows`、`wmic shadowcopy delete`、`wbadmin delete catalog`、`bcdedit recoveryenabled no`、`reagentc /disable` |
| block | `DISK-WIPE` | `format C:`、`diskpart clean`、`Clear-Disk`、`dd of=/dev/...`、`mkfs` |
| block | `DATA-WIPE` | `cipher /w`、`sdelete`（根/家目录） |
| block | `LOG-WIPE` | `wevtutil cl`、`auditpol /clear`、`fsutil usn deletejournal` |
| block | `REGISTRY-WIPE` | `reg delete HKLM/HKU/HKCR/HKCC` |
| block | `ACL-TAKEOVER` | `takeown /f C:\`、`icacls C:\ /reset`、对家目录做同样操作；**纯查询**（`icacls "C:\Program Files\App"`）放行 |
| block | `SERVICE-ACCOUNT` | `sc delete`、`net user ... /delete` |
| block | `SECURITY-TAMPER` | `Set-MpPreference -Disable*`、`netsh advfirewall ... off`、`manage-bde -off` |
| block | `VM-DESTROY` | `wsl --unregister`（含 WSL 内 `rm -rf /mnt/c/Users/...`） |
| block | `BOOT-CONFIG` | `bcdedit`、`bootrec /fixmbr`、`reagentc /disable` |
| block | `FS-PERMISSIONS` / `FORK-BOMB` | `chmod -R 000 /`、`chown -R ... /`、fork bomb |
| block | `ENCODED-CMD` | `powershell -EncodedCommand ...`：**先按 UTF-16LE 解码再递归判定**，解出无害命令放行，解出危险命令或解不出可读文本才拦 |
| block | `SECRET-READ` | `cat .env`、`Get-Content ~/.ssh/id_ed25519`、`cat ~/.aws/credentials`、`~/.dsh/.credentials.yaml`、`.github-mcp-token`、`automation.env`、`*.pem` / `*.key`；`.env.example` 放行 |
| block | `REMOTE-EXEC` / `LOLBAS` | `iwr ... \| iex`、`mshta http`、`regsvr32 /i:http` |
| block | `WRAPPED-DESTRUCTIVE` / `SCRIPT-DELETE` | 包装器 / 内联解释器里的删除命令，仅当目标落在受保护路径上才拦 |
| ask | `GIT-DESTRUCTIVE` | `git reset --hard`、`git clean -fdx`、`git push --force` |
| ask | `CONTAINER-PRUNE` / `CLUSTER-DELETE` / `INFRA-DESTROY` | `docker system prune -a`、`kubectl delete`、`terraform destroy` |
| ask | `DB-DESTRUCTIVE` | `DROP TABLE`、`TRUNCATE` |
| ask | `RECYCLE-BIN` / `POWER-STATE` | `Clear-RecycleBin`、`shutdown /r` |
| ask | `SYSTEM-COMPONENT` / `SCHEDULE-DELETE` | `wusa /uninstall`、`dism /remove-package`、`schtasks /delete` |
| ask | `FS-FIND-DELETE` / `FS-SHRED` / `FS-CWD` | `find . -delete`、`shred`、`rm -rf .` |
| block | `FS-PROTECTED` | `write`/`edit` 指向 `~/.dsh/sessions`、`~/.dsh/memory`、`~/.dsh/AGENTS.md`、`.credentials.yaml`、`.github-mcp-token`、`.mcd-mcp-token`、`.ssh`、`.aws`、`.gnupg`、`C:\Windows`、`Program Files`；`apply_patch` 的 `*** Update File:` 头同样检查；`read` 读同一批秘密文件也拦（否则 `cat .env` 拦了、`read .env` 却畅通） |

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

判定是纯字符串正则，在每次工具调用前跑一次（pre-execute + 单调 guard，共两次）：1.2.0 实测典型命令约 **6–7 µs**（79 字节样本 20000 次均值 6.7 µs，44 条探针平均 0.2 ms/次含启动开销），长命令线性增长；比进程启动低五个数量级；不注册工具、不增加提示词 token、不做文件 IO。对模型延迟的影响可忽略。

## 局限（必须知道）

- 它**不是沙箱**：只拦命令字符串里看得见的模式。`[Environment]::GetFolderPath()` / `SpecialFolder` 取值现在按家目录拦下了，但 `-join` 之类的运行时拼路径、运行时生成脚本、GUI 自动化（`computer_use` 往终端里打字）、自写二进制仍能绕过。
- **文件工具只审落点、不审语义**：`write` / `edit` / `apply_patch` 的目标路径命中保护清单会拦，但把破坏性内容写进一个普通文件（例如 `C:\temp\x.ps1`）本身不拦；随后按路径执行时也看不见内容。`run_code` 里 `child_process` 删目录同样绕过。
- **不审脚本内容**：`powershell -File verify.ps1`、`python x.py`、`node x.js` 只按路径执行，脚本里写什么它看不见；先写脚本再执行是现成绕过路径。
- `-EncodedCommand` 现在会解码后复查；但多层编码（`base64` 再 `FromBase64String`）或运行时拼接的载荷仍可能逃逸。
- 命令别名 / 函数覆盖（`function rm {}`）不在覆盖范围。
- `-WhatIf` 预览也会被拦（宁可误拦）。
- 仍应保持：测试用 `workspace-write` 沙箱、破坏性操作要审批、升级前备份 `.dsh/.claude/.doubao`。

## 运行测试

```powershell
cd "C:\DSH Plugin\dsh-destructive-guard"
node --test
```

`test/classify.test.mjs` 覆盖家目录、盘根、恢复/日志/注册表、编码命令（解码语义）、路径穿越、WSL 路径、包装器、多行与 `if`/`try` 块、变量污点、别名管道、敏感子目录、跨语句假管道与 `?` 回归、临时/项目内清理放行、秘密读取、write/edit/apply_patch 落点等；`test/hook.test.mjs` 用假 ctx 覆盖 `never` 降级、`ask` 不变、配置默认 `never`、读不到 approval 回退 `ask`、文件工具 deny。共 28 条，只调用纯函数与假对象，不执行任何命令，也不碰 `~/.dsh`。

## v1.2.0：按目标判定

1.1.0 的问题是“命令里只要出现受保护路径就拦”，于是 `Remove-Item %TEMP%\x.mjs`、删 `_build\tex` 里的 png、`icacls "C:\Program Files\App"` 纯查询都被拦下。1.2.0 改成：

- 先分词取出**删除动词的真实目标**（含 `$var = '...'` 单层展开、`foreach ($d in (Get-ChildItem $home))` 的循环变量、`\\?\` 设备前缀、`/c/Users/...` MSYS 路径、`$home`/`$env:USERPROFILE`/`~`），再按目标深度判定；
- `%TEMP%` 与 `C:\Windows\Temp` 一律放行；家目录根、`.ssh`/`.aws`/`.gnupg` 任意深度、`.dsh/sessions|memory` 任意深度、`.dsh` 其它 ≤2 层、`Desktop/Documents/Downloads/AppData` 等一级目录整体、受保护根、系统目录、盘根仍拦；
- 管道只在**同一条语句**内按生产者目标判定：`ls $home | ri` 拦，`gci 项目目录 | Remove-Item` 放行；
- `WRAPPED-DESTRUCTIVE` / `SCRIPT-DELETE` 只在目标受保护时才拦；`ACL-TAKEOVER` 要 `takeown /f` 或 `icacls` 的变更开关，纯查询放行；`EncodedCommand` 解码后递归判定。

实测：从本机 122 个会话、7201 次 `pwsh` 调用里找出 53 次真实拦截（占 0.74%，其余误命中是日志正文里引用了护栏文案），其中 11 个典型误拦（删 TEMP 文件、删构建产物、删测试 profile、删插件状态目录、变量中转删桌面 txt、`icacls` 查询、Everything 启动脚本）现在全部放行；`$home`、`$env:USERPROFILE`、`.ssh\id_rsa`、`.dsh\memory`、读 `.credentials.yaml` 仍全部拦下。

## 与本机 cc-safety-net 的关系（v1.2.0）

本机曾并存 `cc-safety-net` 2.8.2。对比结论：它在**秘密读取**（`.env`/`.ssh`/云凭据/CLI 凭据）、git 破坏性操作（`reset --hard`、`clean -fdx`、`push --force`、`stash drop`）和动态 shell 源（`curl|bash`、`iex`）上更细；但只挂单调 guard、无 `ask` 分层，Windows 侧几乎空白（实测 `vssadmin delete shadows`、`format C:`、`Clear-Disk`、`takeown /f C:\`、`reg delete` 全部放行），且会连 `~/.ssh/known_hosts` 一起拦。

v1.2.0 把它的强项吸收进来（`SECRET-READ` 规则、git 规则、动态源拦截），并补上它不认识的 DSH 凭证（`.dsh/.credentials.yaml`、两个 MCP token、`automation.env`）；**故意不跟**它“一刀切 block”的部分，仍然用 `ask` 分层。因此本机不再需要 `cc-safety-net`，停用它可避免重复拦截与两套理由。

## 对诺亚方舟事件的覆盖

| 当时发生的事 | 现在 |
| --- | --- |
| 22:36 `Remove-Item -Recurse -Force $home` | 拦（`FS-HOME`），多行 / 块内 / 变量中转的写法也拦 |
| 15:24 安装流程直接删 `~/.dsh`、`~/.claude` | **不覆盖**：不是 shell 命令，插件看不见 |
| 先写 `verify.ps1` 再 `powershell -File` 执行 | **不覆盖**：只认命令行，不读脚本内容 |

所以它是“降低再犯概率”的一道闸，不是复现免疫；配合审批模式与升级前备份才完整。

## 关闭

临时关闭：设置环境变量 `DSH_GUARD=off`（需要重启/重载插件）；或从 profile 的 `dsh.profile.bundles` 移除本 bundle。
