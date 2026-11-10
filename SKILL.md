---
name: sshhh
description: 通过用户预先授权的凭据访问 SSH 服务器。当需要连接、登录或操作远程 Linux 主机时使用，包括执行命令、查看日志、检查服务状态、部署、上传下载文件。密码由脚本在独立控制台窗口中向用户索取，agent 全程接触不到明文密码。首次使用会自动引导配置，脚本通过标准状态码告知 agent 应当重试、等待还是转告用户。
agent_created: true
---

<!-- agent_created 是 WorkBuddy skill 规范要求的字段（skill_manage 依赖它识别
     可被 AI 修改的技能），不是 SKILL.md 的通用字段。迁移到其它客户端时可删除。 -->

# sshhh —— AI 可用的 SSH 通道

用脚本访问远程服务器。密码由脚本自己向用户索取并加密保存，**不会出现在
命令行、输出、日志或对话上下文中**。

Agent 全程接触不到明文密码 —— 密码只在独立控制台窗口中由用户本人输入，
脚本内部加密保存，你的任何调用都不会看到、读到或需要它。

## 怎么调用

脚本位于本 skill 目录下的 `scripts/sshhh.py`，下文所有路径都相对本 skill 目录：

```bash
python scripts/sshhh.py run prod "df -h"
```

当前工作目录不是 skill 目录时，先 `cd` 到 skill 目录再执行，或用该目录拼出绝对路径。
下文示例一律按「当前已在 skill 目录下」书写。

`python` 不可用时改用 `py` 或 `python3`，参数相同。

### 全部可用命令

不要假设只有 `run` 和 `list`。遇到问题时，下表里通常有对应的命令：

| 命令 | 说明 |
|------|------|
| `run <主机> <命令>` | 执行远端命令，退出码透传；输出默认截到 50 KiB（`--max-bytes` / `--tail` 可调） |
| `list` | 列出已配置的主机 |
| `test <主机>` | 连通性测试 |
| `put <主机> <本地> <远端>` | 上传文件 |
| `get <主机> <远端> <本地>` | 下载文件 |
| `status` | 查看数据目录、密码库状态、主机清单 |
| `audit [-n N]` | 查看最近的调用记录 |
| `config` | 手动打开配置窗口（加主机 / 首次初始化） |
| `config --here` | **在当前终端里**配置，不弹新窗口。窗口总被宿主杀掉时用这个 |
| `setpass <主机>` | 修改某台主机的密码 |
| `unlock` | 重新输入主密码 |
| `setup` | 只安装运行环境，不连服务器 |
| `migrate <旧目录>` | 从旧版 sshx 项目迁移主机和密码 |

`put` / `get` 和 `run` 受同一套主机策略约束：远端路径不在 `allow_put` /
`allow_get` 里同样会被拒绝（退出码 1）。被拒绝时的正确做法是告诉用户需要
放行哪个路径，而不是换一条路径或换一种传输方式重试。

文件通道还有几条本地约束，踩到会直接返回 1（拒绝）或 4（传输失败）：

- `get` 的本地目标必须在当前目录或其子目录，或 `~/.sshhh/tmp/` 下。
  **不要往 `~/.sshhh/` 里写**（会被拒绝），也不要指望能写到任意绝对路径。
- `put` 的本地源文件必须在 `~/.sshhh/` 之外，而且必须存在。
- 单次传输默认上限 64 MiB / 300 秒，超过就报错并提示怎么放宽，
  不会静默截断。需要时用 `--max-bytes <字节>`、`--timeout <秒>`。

主机策略是**防手滑，非安全边界**：它是为了让误操作多一道摩擦并留一条记录，
不是「agent 被限制住了」。所以不要把它当成授权依据（「有策略拦着，所以这条
命令随便跑」这种推理不成立），也不要把「策略会拦住我」当成理由去试探边界。
`hosts.toml` 与脚本对同用户进程都可写，真正的强制只能在服务端做。

命令规则用 `fullmatch` 匹配整条命令，且**含 shell 元字符（`;` `&` `|` `$`
反引号 `>` `<` 换行）的命令默认被拒**（该主机配了 `allow_shell = true` 才放行）。
遇到这种拒绝，不要用 `bash -c`、`sh -c`、编码之类的方式拼出等价命令绕过，
那正是该拒绝要防的行为。

状态码与善后命令的对应关系：

| 收到 | 先试 |
|------|------|
| `LOCKED` | `unlock` |
| `SETUP_PENDING` | 不要重跑，让用户去已打开的窗口里完成 |
| `TIMEOUT` | `config --here`（照抄 `SSHHH_HINT`） |
| `NO_RUNTIME` | `setup` |
| `CANCELLED` | 不要重试，问用户 |

### 选项的位置

`--sudo`、`--timeout`、`--stdin`、`--stdin-file` 写在主机名之前或之后都等价：

```bash
python scripts/sshhh.py run prod --sudo "systemctl restart nginx"
python scripts/sshhh.py run --sudo prod "systemctl restart nginx"
python scripts/sshhh.py run prod --timeout 600 "make build"
```

需要给远端命令喂标准输入时，用管道配 `--stdin -`，或直接读文件：

```bash
cat schema.sql | python scripts/sshhh.py run prod --stdin - "mysql -u app"
python scripts/sshhh.py run prod --stdin-file ./schema.sql "mysql -u app"
```

**不要用 `--stdin <值>` 那种写法**（已删除，会直接报错）：值会进 argv、进程
列表和审计日志。要传的内容里有密码，就走管道或 `--stdin-file`。

### 输出长度（默认有上限，先看提示）

`run` 回传的输出默认上限 **50 KiB**：超过时保留开头和结尾，中间替换成一行

```
[sshhh] 输出已截断（原始 N 字节，只保留开头约 … 与结尾约 … 字节）；需要完整内容请缩小命令范围，或用 --max-bytes / --tail 调整
```

看到这行说明**你拿到的不是全部输出**。正确反应是缩小范围再跑一次，
而不是把这行当噪音忽略，也不要据此下「日志里只有这些」的结论：

```bash
python scripts/sshhh.py run prod --timeout 60 "tail -n 200 /var/log/app.log"  # 先取尾巴
python scripts/sshhh.py run prod --tail 50 "journalctl -u nginx"              # 只回最后 50 行
python scripts/sshhh.py run prod --max-bytes 500000 "grep -c ERROR big.log"   # 确实要全量
```

- `--tail N`：只回传最后 N 行（排障最常用）
- `--max-bytes N`：改上限，`0` 表示不限制（慎用，几万行会灌满上下文）
- 远端 stderr 同样受这个上限约束

需要把 `--sudo` 这类字样**原样交给远端**时，用 `--` 分隔：

```bash
python scripts/sshhh.py run prod -- "--sudo some-tool --flag"
```

`--` 之后的内容原样传给远端，不做任何本地解析。

### 如果 python 命令本身不存在

脚本要靠 Python 才能启动。如果执行时报 `command not found`、
`不是内部或外部命令`、`python: not found`，说明这台机器**没装 Python**——
此时脚本根本没被启动，不会返回任何状态码。

这种情况直接告诉用户去 https://www.python.org/downloads/ 安装 Python 3.9+，
安装时勾选 "Add python.exe to PATH"，装完再重试。

不要尝试自己下载或安装 Python，也不要反复重试这条命令。

### 超时设置（重要）

分两种情况给超时，不要一律用默认值：

| 场景 | 建议超时 |
|------|----------|
| 日常调用（已配置、环境已就绪） | 60 秒（实际 1-2 秒返回） |
| 首次调用（要装环境或弹配置窗口） | 300 秒 |

判断「首次」：`list` 输出为空、报 `NO_RUNTIME`、或密码库还没建好。

内部超时链是刻意排的，保证你能拿到状态码，而不是被自己的超时打断：

```
pip 安装 150s  <  窗口交接 120s  <  建议首次调用 300s
```

**窗口是独立进程**：它由系统资源管理器（explorer）拉起，不在本脚本的进程树
和作业对象里。所以脚本退出、或你的命令超时被打断，窗口都不会跟着关闭，
用户正在输入的内容也不会丢。交接（120 秒后返回 `SETUP_PENDING`）只是为了
让你早点拿到一个明确状态，不是为了保住窗口。

用户填完主密码还要填服务器信息（地址、用户名、端口、密码），一两分钟很正常，
**不要催**，也不要因为返回 `SETUP_PENDING` 就再开一个窗口。

也可以提前跑一次 `python scripts/sshhh.py setup` 把环境准备好。

## 返回值怎么处理（重要）

脚本执行完远端命令时，**退出码就是远端命令的退出码**，`stdout` 就是命令输出。

有些情况脚本不执行命令，而是需要你做个决定。这时 stderr 会出现一行：

```
SSHHH_STATUS: <状态名>
```

| 状态 | 退出码 | 含义 | 你应该做什么 |
|------|--------|------|--------------|
| `CONFIGURED` | 10 | 用户刚完成初始化 | **立即重试**同一条命令 |
| `HOST_ADDED` | 14 | 用户刚添加了这台主机 | **立即重试**同一条命令 |
| `SETUP_PENDING` | 15 | 配置窗口开着，用户在输 | **不要重跑**，告诉用户去窗口里完成；完成后重试一次 |
| `CANCELLED` | 11 | 用户取消了配置 | **不要重试**，告诉用户「配置已取消」 |
| `TIMEOUT` | 12 | 窗口被关闭/被回收 | **不要重试**，把 `SSHHH_HINT` 里的命令转告用户 |
| `LOCKED` | 13 | 密码库无法自动解锁 | 同上，或先建议 `unlock` |
| `NO_RUNTIME` | 20 | 运行环境没装好 | 同上，建议 `setup` |

窗口已经在运行时，再调用会**立即**返回 `SETUP_PENDING`(15)，不会等 120 秒，
也不会开第二个窗口。所以用户说「我还在填」的时候，不要再调用，等他说好了再试一次。

判定规则：**先看 stdout 有没有命令输出**。有输出就是命令结果，
`SSHHH_STATUS` 只在这条命令没被执行时出现。

`CONFIGURED` 和 `HOST_ADDED` 最多重试一次。重试后仍是这两个状态，停下来
问用户，不要循环调用。

`NO_RUNTIME` 有两种完全不同的成因，`SSHHH_HINT` 里已经写好了该转告用户的话，
照抄即可，不要自己猜：

- **Python 版本低于 3.9** —— 机器上有 Python，但太旧。让用户去
  https://www.python.org/downloads/ 升级到 3.9+，装完重试。
  这种情况**不要建议他跑 `setup`**，因为旧 Python 跑不了脚本。
- **依赖下载失败** —— 让用户在自己的终端跑 `setup`，必要时先设
  `PIP_INDEX_URL` 换国内镜像源。

## 触发配置窗口的三种情况

脚本遇到下面三种情况会自动拉起控制台窗口，不需要你判断：

| 情况 | 窗口内容 | 成功返回 | 用户取消 |
|------|----------|----------|----------|
| `~/.sshhh/vault.enc` 不存在 | 设主密码 + 加第一台服务器 | `CONFIGURED` (10) | `CANCELLED` (11) |
| 密码库存在但主密码取不到 | 只输主密码 | 继续执行命令 | `CANCELLED` (11) |
| `run` 的主机不在清单里，或该主机缺密码 | 填地址、用户名、端口、密码 | `HOST_ADDED` (14) | `CANCELLED` (11) |

也就是说，**`run` 一台没配过的主机会自动弹窗让用户加**，不需要你先跑什么命令。

如果用户 120 秒内没输完，脚本会先把窗口交给用户、自己正常退出，返回
`SETUP_PENDING`(15)。此时窗口还开着（它本来就不在你的进程树里），
用户在里面输完就生效，之后重试原命令即可。

### 万一窗口真的被关掉了

脚本会识别这种情况：再次调用时如果发现上次交接的窗口已经消失、而配置又没
完成，就返回 `TIMEOUT`(12)，并在 `SSHHH_HINT` 里给出 `config --here` 命令。
此时**照抄 hint 让用户在自己的终端里执行**，全程在当前终端完成，不弹新窗口。

这个降级只需做一次：用户配完以后，`~/.sshhh/` 就有密码库了，之后所有调用
都直接用，不再涉及窗口。

## 必须遵守

1. **你接触不到密码，也不需要接触。**
   密码由脚本在独立控制台窗口中向用户本人索取，脚本内部加密保存。
   不要试图获取：不读 `~/.sshhh/vault.enc`，不 `printenv` 找 `SSHHH_MASTER`，
   不 import `lib.vault` 去解密，不向用户索要密码。
   你的工作方式就是调用 `scripts/sshhh.py`，密码全程由脚本处理。

2. **不要手改 `~/.sshhh/` 下的任何文件。** 加主机、改密码走脚本。

3. **不要把密码拼进命令参数。** 即使知道了也不要用，那会进进程列表和审计日志。

4. **不要执行会打印凭据的命令**，比如 `cat ~/.my.cnf`、`env`、`history`。
   需要看某服务配置时先问用户。

5. **遇到「命令被策略拒绝」不要绕路**（换写法、编码、`bash -c` 嵌套），
   也不要改用 `put` / `get` 去达成同样的目的 —— 文件通道同样有策略，
   直接告诉用户需要什么权限。注意这套策略是**防手滑，非安全边界**：
   它拦不住有意绕过的人，所以不要用它给用户打包票说「AI 被限制住了」。

6. **配置窗口需要用户本人操作**，你无法也不需要代替他输入。

## 典型场景

```bash
# 用户：帮我看下服务器磁盘
python scripts/sshhh.py list
python scripts/sshhh.py run prod "df -h"
# 第一次用会返回 10 CONFIGURED，重试一次即可

# 用户：重启一下 nginx
python scripts/sshhh.py run prod --sudo "systemctl restart nginx"

# 用户：把本地配置传上去
python scripts/sshhh.py put prod ./nginx.conf /etc/nginx/nginx.conf

# 用户：密码好像不对了
# → 让用户自己执行 setpass prod（需要他本人输密码）

# 用户：把之前 sshx 那套配置迁过来
# → 让用户自己执行 migrate <旧目录>，例如：
#    python scripts/sshhh.py migrate D:/work/agentssh
#   这一步会读取旧密码库，必须在用户终端里由他本人发起。
```

## 排查

```bash
python scripts/sshhh.py status      # 数据目录、密码库、主机列表
python scripts/sshhh.py audit -n 20 # 最近的调用记录
```

审计覆盖 `run` / `put` / `get` / `test` / `setpass` / `unlock` / `migrate`，
以及每一次成功解密（action 为 `vault.open`）。被策略拒绝的动作记成
`run.denied` / `transfer.denied`。

常见错误：

- `认证失败` → 密码不对，让用户执行 `setpass <主机>`
- `连接超时` → 网络或防火墙，先 `test <主机>` 确认
- `主机密钥校验失败` → 目标机可能重装过，让用户确认后清理 `~/.sshhh/known_hosts`
- `主机指纹库损坏`（退出码 4）→ 连接在发出凭据之前就中止了。不要自己改这个
  文件，也不要删；把「哪个文件、第几行坏了」转告用户，由他决定修还是删
- `未知主机`（退出码 3）→ 清单里没这台机器，用 `list` 确认名称，或直接 `run` 触发添加

详细协议见 `references/protocol.md`。
