# TRAP 主网部署指南

本文说明如何在 Linux 服务器上部署 TRAP 节点（`trapcoind`）和 solo 挖矿矿池（ckpool），并让 ASIC 矿机接入挖矿。

流程经过两次实际验证：
- 2026-09-28 本地彩排：Bitaxe 矿机经 ckpool 挖到第 2125 块，验证了区块同步、挖矿奖励成熟、钱包转账，
  以及第 2016 块难度从 1 调整到 4；
- 2026-09-28 云服务器部署：Bitaxe 经公网连到云服务器上的 ckpool 出块，家里的钱包同步到新区块。
  部署中遇到的问题都已写进对应步骤和文末的"报错对照表"。

**每一步最后都有"验证"命令，确认通过再做下一步。** 问题越早发现越好查。

## 架构

```
ASIC 矿机 ──Stratum:3333──> ckpool（solo） ──RPC:4199──> trapcoind ──P2P:4200──> 其他 TRAP 节点
```

| 端口 | 用途 | 是否对外开放 |
|---|---|---|
| 4200 | P2P，节点之间通信 | 开放（见第 4 节） |
| 4199 | RPC，仅供本机的 `trapcoin-cli` 和 ckpool 使用 | **绝不开放** |
| 3333 | Stratum，矿机连接矿池 | 开放（见第 4 节） |

节点和矿池都以专用的 `trap` 用户运行，配置文件放在 `/etc/trap/`，数据放在 `/var/lib/`。

## 1. 准备服务器

- 系统：Ubuntu 22.04 / 24.04
- 起步配置：2 核、4 GB 内存、50 GB 硬盘
- 建议至少 2 台位于不同地区的公网服务器，互相 `addnode`，避免单点故障

```bash
sudo apt install -y build-essential cmake pkgconf python3 git curl \
    libevent-dev libboost-dev libsqlite3-dev \
    autoconf automake libtool yasm
sudo useradd --system --create-home --shell /usr/sbin/nologin trap
```

`trap` 用户**必须先创建**：服务文件里写了 `User=trap`，没有这个用户，服务会启动失败，
报 `Job for trapcoind.service failed because the control process exited with error code`。

**验证：**`id trap` 能显示用户信息。

## 2. 编译安装 trapcoind

```bash
git clone https://github.com/TrapboT-del/Trapcoin.git
cd Trapcoin
cmake -B build -DBUILD_TESTS=OFF
cmake --build build -j"$(nproc)"
sudo cmake --install build          # 安装到 /usr/local/bin
```

**验证：**`trapcoind -version` 显示 `Trap Core daemon version v0.42.0`。

## 3. 配置并启动 trapcoind

```bash
sudo mkdir -p /etc/trap
sudo cp contrib/init/trap.conf.example /etc/trap/trap.conf
python3 share/rpcauth/rpcauth.py trapmine
```

`rpcauth.py` 会打印两样东西，用途不同，不要混淆：

```
String to be appended to bitcoin.conf:
rpcauth=trapmine:1f2e3d4c...$9a8b7c6d...     ← ① 整行替换到 /etc/trap/trap.conf 的 rpcauth= 行
Your password:
Xy7_ExampleOnlyNotARealPassword0000000000000  ← ② 这是密码，第 6 步填进 ckpool.conf 的 "pass"
```

- ①里 `$` 前后是盐值和哈希，节点用它来验证密码，本身**不能**当密码用；
- **把②记下来**，第 6 步要用；
- ①和②是**配套的一组**。每运行一次 `rpcauth.py` 都会生成新的一组，
  如果重新生成，`trap.conf` 和 `ckpool.conf` **两边都要换**，并重启 `trapcoind`。

把模板里的占位行 `rpcauth=trapmine:REPLACE_WITH_SALT_AND_HASH` 替换成①，然后启动：

```bash
sudo nano /etc/trap/trap.conf        # 替换 rpcauth= 行；有其他 TRAP 节点就加 addnode=IP:4200
sudo cp contrib/init/trapcoind.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now trapcoind
```

**验证：**

```bash
sudo -u trap trapcoin-cli -datadir=/var/lib/trapcoind -conf=/etc/trap/trap.conf getblockchaininfo
curl -s --user 'trapmine:你的密码②' --data-binary '{"method":"getblockcount"}' http://127.0.0.1:4199/
```

第一条显示 `"chain": "main"` 和 TRAP 创世区块哈希 `0000000008d755…`；
第二条返回 `{"result":…,"error":null}`，说明密码②能通过认证。

> `trapcoin-cli` 的格式是 `trapcoin-cli [连接参数] <命令>`，最后的命令不能省略，
> 否则报 `too few parameters (need at least command)`。以 root 运行时可以省掉 `sudo -u trap`。

## 4. 防火墙：开放 4200 和 3333 端口

服务器需要对外开放以下端口，**两层防火墙都要放行**，缺一不可：

| 端口 | 协议 | 来源 | 用途 |
|---|---|---|---|
| 22 | TCP | 你的电脑（或所有） | SSH 远程登录，**必须保留，否则会连不上服务器** |
| **4200** | TCP | 所有（`0.0.0.0/0`） | P2P，其他 TRAP 节点连进来 |
| **3333** | TCP | 所有（`0.0.0.0/0`） | Stratum，矿机连接矿池；矿机不连本机矿池时可不开 |
| 4199 | — | — | RPC，**不要开放** |

**第一层：云平台安全组。** 在云服务商的网页控制台里，找到这台服务器的"安全组 / 防火墙"，
添加入站规则：TCP 4200、TCP 3333，来源 `0.0.0.0/0`。

**第二层：服务器系统防火墙（ufw）。**

```bash
sudo ufw allow OpenSSH       # 务必第一个执行，否则 enable 后会断开远程连接
sudo ufw allow 4200/tcp      # P2P
sudo ufw allow 3333/tcp      # Stratum
sudo ufw enable
sudo ufw status              # 确认三条规则都是 ALLOW
```

在 solo 模式下，别人连上 3333 端口也只能给他自己的地址挖矿，拿不走你的币；
如果想只允许自己的矿机，可以改用 `sudo ufw allow from 矿机的公网IP to any port 3333 proto tcp`。

**验证：**从另一台机器（不要用 VMware NAT 虚拟机测，它会让任何端口都显示为连通）连接 4200，
或者在第 8 步让家里的钱包连上来。

## 5. 首次上线准备（新链挖第一个块前必须做）

主网节点只有**同时满足两个条件**，才会给矿池出挖矿任务。否则 ckpool 拿不到任务，
矿机能连上矿池但**收不到任何回复，也不报错**，就一直干等。

### 5.1 解除初始同步状态：开启 maxtipage

链顶超过 24 小时没有新块，节点就认为自己还在初始同步中，报 `Trap Core is in initial sync`。
新链只有创世区块时必然如此，所以要放宽这个限制：

```bash
sudo sed -i 's/^#maxtipage=/maxtipage=/' /etc/trap/trap.conf
grep -n maxtipage /etc/trap/trap.conf           # 必须是 maxtipage=315360000，行首没有 #
sudo systemctl restart trapcoind
```

**验证**（重启后等 15 秒）：

```bash
grep maxtipage /var/lib/trapcoind/debug.log | tail -1     # Config file arg: maxtipage="315360000"
sudo -u trap trapcoin-cli -datadir=/var/lib/trapcoind -conf=/etc/trap/trap.conf getblockchaininfo | grep initialblockdownload
```

应为 `"initialblockdownload": false`。链开始正常出块后，把这一行重新注释掉（行首加 `#`）并重启。

### 5.2 保证至少有一个对等节点：陪伴节点

节点没有任何连接时，报 `Trap Core is not connected!`。只靠家里的电脑连过来并不可靠：
它一关机或断网，矿池就停工。在其他节点加入之前，在**同一台服务器**上再运行一个只连本机的陪伴节点：

```bash
sudo tee /etc/trap/companion.conf > /dev/null <<'EOF'
# Companion node: connects to the local trapcoind so it always has a peer
server=0
listen=0
dnsseed=0
fixedseeds=0
listenonion=0
connect=127.0.0.1:4200
EOF
sudo chown root:trap /etc/trap/companion.conf && sudo chmod 640 /etc/trap/companion.conf
sudo cp contrib/init/trapcoind-companion.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now trapcoind-companion
```

有了其他长期在线的 TRAP 节点后，可以停掉它：`sudo systemctl disable --now trapcoind-companion`。

**验证：**

```bash
sudo -u trap trapcoin-cli -datadir=/var/lib/trapcoind -conf=/etc/trap/trap.conf getconnectioncount
sudo -u trap trapcoin-cli -datadir=/var/lib/trapcoind -conf=/etc/trap/trap.conf getblocktemplate '{"rules":["segwit"]}' | grep '"height"'
```

连接数至少为 1，第二条显示 `"height": 1`（或当前高度 +1），说明节点已经能出挖矿任务。

## 6. 编译安装并启动 ckpool

ckpool 需要一个 TRAP 专用补丁（见文末"已知问题"），用仓库里的脚本编译：

```bash
contrib/ckpool/build-ckpool.sh ~/ckpool
sudo install ~/ckpool/src/ckpool /usr/local/bin/ckpool
sudo cp contrib/ckpool/ckpool.conf.example /etc/trap/ckpool.conf
```

脚本最后一行显示 `Built …/src/ckpool` 才算成功；如果报 `no TRAP patches found`，先 `git pull`。

编辑 `/etc/trap/ckpool.conf`：
- `pass`：第 3 步 `rpcauth.py` 在 `Your password:` 下面打印的**密码②**，不是 `rpcauth=` 那行里的哈希；
- `btcaddress`：一个你控制的 TRAP 地址（`trap1...`），矿池启动时会校验它，无效则直接退出。

**设置权限**（ckpool 以 `trap` 用户运行，读不到配置时不会报错，而是悄悄改用内置默认值）：

```bash
sudo chown root:trap /etc/trap/ckpool.conf && sudo chmod 640 /etc/trap/ckpool.conf
sudo -u trap cat /etc/trap/ckpool.conf > /dev/null && echo "trap 用户可以读"
python3 -m json.tool /etc/trap/ckpool.conf > /dev/null && echo "JSON OK"
```

然后启动：

```bash
sudo cp contrib/init/trap-ckpool.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now trap-ckpool
```

**验证：**

```bash
sudo tail -5 /var/lib/trap-ckpool/logs/ckpool.log
```

应出现 `Connected to bitcoind: 127.0.0.1:4199`，且没有 `401`、`8332`、`No bitcoinds active!` 字样。

> **重启顺序**：`trapcoind` 重启后，ckpool 和陪伴节点会自动重连，一般不用管。
> 如果矿机长时间收不到回复，再执行 `sudo systemctl restart trap-ckpool`。

## 7. 矿机配置（以 Bitaxe / AxeOS 为例）

| 设置项 | 值 |
|---|---|
| Stratum Host | 服务器 IP（不要带 `stratum+tcp://` 前缀） |
| Stratum Port | `3333` |
| Stratum User | `你的TRAP地址.矿机名`，例如 `trap1q....bitaxe1` |
| Stratum Password | `x` |
| Suggested Difficulty | 链的难度很低时设为 `1`（默认 1000 会丢弃大部分有效区块） |
| Fallback 矿池 | 留空，或填同一地址；不要填 `x` 之类的无效地址 |

solo 模式下，挖到的区块奖励全部归用户名里的 TRAP 地址。

**验证：**矿机日志出现 `rx: {"result":true,…}` 和 `FOUND BLOCK`；
ckpool 日志出现 `Authorised client … worker 你的地址.矿机名`。

## 8. 让其他电脑的钱包连接云节点

在家里电脑的 `trapcoin-qt` 数据目录（Linux 为 `~/.trap/`）里新建 `trap.conf`：

```ini
addnode=服务器IP:4200
```

然后**重启钱包**才会生效。不想重启的话，在钱包菜单 **窗口 → 控制台** 里执行：

```
addnode 服务器IP:4200 add
```

必须用 `add`：它会一直保持连接，断了自动重连。`onetry` 只连一次，
服务器上的 `trapcoind` 一重启就断开，之后不会再连。

**验证：**控制台执行 `getpeerinfo` 能看到服务器 IP；钱包的区块高度和服务器一致。

## 报错对照表

| 现象 / 报错 | 原因 | 解决 |
|---|---|---|
| `Job for trapcoind.service failed because the control process exited with error code` | 没有 `trap` 用户 | 第 1 步 `useradd` |
| `trapcoind` 启动失败：`Unable to start HTTP server`，`debug.log` 里有 `Invalid -rpcauth argument` | `trap.conf` 的 `rpcauth=` 还是占位符，或格式不对 | 第 3 步替换成 `rpcauth.py` 打印的① |
| `too few parameters (need at least command)` | `trapcoin-cli` 最后没写命令 | 在末尾加上命令，如 `getblockchaininfo` |
| `Trap Core is in initial sync and waiting for blocks...` | `maxtipage` 没生效（行首还有 `#`，或没重启） | 第 5.1 步，用 `debug.log` 确认 |
| `Trap Core is not connected!` | 节点没有任何连接 | 第 5.2 步陪伴节点；钱包用 `addnode … add` |
| 矿机能连上矿池，发出 subscribe 后一直没有回复，也不报错 | ckpool 拿不到挖矿任务 | 按上面两行排查，然后看 ckpool 日志 |
| ckpool 日志 `HTTP/1.1 401 Unauthorized`、`No bitcoinds active!` | `pass` 不对：填成了哈希，或和 `trap.conf` 的 `rpcauth` 不是同一组 | 第 3 步的 `curl` 验证密码；两边换成同一组并重启 `trapcoind`、ckpool |
| ckpool 日志 `Failed to connect socket to localhost:8332` | ckpool 读不到配置文件（权限 `root:root`），用了默认值 | 第 6 步 `chown root:trap`、`chmod 640` |
| `Fatal: btcaddress invalid according to bitcoind` | `btcaddress` 不是有效的 TRAP 地址 | 换成钱包生成的 `trap1…` 地址 |
| `build-ckpool.sh` 报 `no TRAP patches found` | 仓库不是最新 | `git pull` 后重新运行 |
| 节点拒绝区块 `bad-cb-height` | ckpool 没打 TRAP 补丁 | 用 `build-ckpool.sh` 重新编译 |
| 矿机日志 `diff … of 1000`，出块很少 | 矿机建议难度是 1000 | 第 7 步 Suggested Difficulty 改为 1 |
| 钱包一直显示"落后 xx 小时" | 链上没有新块，或钱包没连上节点 | 确认矿池在出块；第 8 步 |
| 日志反复 `tor: Error connecting to address 127.0.0.1:9051` | 本机没有 Tor，节点反复尝试 | `trap.conf` 加 `listenonion=0`（新模板已包含） |
| `ufw enable` 后 SSH 断开 | 没先放行 SSH | 到云平台网页控制台登录，执行 `ufw allow OpenSSH` |

## 已知问题与经验

- **ckpool 的 BIP34 高度编码**：TRAP 从第 1 块起启用 BIP34，第 1–16 块的 coinbase 高度必须编码为
  `OP_1`…`OP_16`。原版 ckpool 只在 regtest 下这样做，主网会被节点以 `bad-cb-height` 拒绝。
  `contrib/ckpool/0001-bip34-minimal-height-encoding.patch` 修正了这一点，`build-ckpool.sh` 会自动打上。
- **份额难度**：ckpool 的 `maxdiff` 管不住矿机主动建议的难度（`mining.suggest_difficulty`）。
  Bitaxe 默认建议 1000，这会让矿机丢弃大部分难度在 1–1000 之间的有效区块。
  链难度还很低时，把矿机的 Suggested Difficulty 改为 1；难度升上来以后再调回默认值，
  并把 `ckpool.conf` 里的 `maxdiff` 删掉或调大。
- **初期出块极快**：难度 1 时，单台 Bitaxe 约 1.6 秒出一块，孤块率约 13%。
  难度每 2016 块最多 ×4，要经过约 9 轮调整才能稳定在 10 分钟一块，
  这期间会快速产出大量 TRAP。若要让他人公平参与，需要在上线前决定初始难度方案。
- **ckpool 读不到配置文件时不会报错**，而是悄悄改用内置默认值（`localhost:8332`）。
  `trap-ckpool.service` 会在启动前用 `trap` 用户检查能否读取配置，读不到就直接启动失败，
  `systemctl status trap-ckpool` 里能看到。
- **`inconclusive`**：ckpool 日志里的 `SUBMIT BLOCK RETURNED: inconclusive` 表示过期份额产生的孤块，属正常现象；
  `bad-*` 开头的才是真正的拒绝。
- **Bitaxe 的 `Failed to process mining notification`**：收到新任务时固件会打印这一行，
  但任务照常挖、照常提交，不影响挖矿。
- **区块版本号各不相同**：Bitaxe 使用版本滚动（ASICBoost），ckpool 支持，属正常现象。
- **虚拟机网络**：在 VMware NAT 虚拟机里测试时，需要在"虚拟网络编辑器"里添加端口转发
  （主机 3333 → 虚拟机 3333），并在 Windows 防火墙放行 3333，矿机填宿主机的局域网 IP。
  另外，NAT 会替虚拟机完成 TCP 握手，所以在虚拟机里测端口"能连上"不代表对方真的开放。

## 日常运维

```bash
sudo systemctl status trapcoind trapcoind-companion trap-ckpool
sudo journalctl -u trap-ckpool -f
sudo -u trap trapcoin-cli -datadir=/var/lib/trapcoind -conf=/etc/trap/trap.conf getmininginfo
sudo tail -f /var/lib/trap-ckpool/logs/ckpool.log                  # 出块、提交结果
sudo grep Authorised /var/lib/trap-ckpool/logs/ckpool.log | tail   # 谁连上了矿池
sudo cat /var/lib/trap-ckpool/logs/pool/pool.status                # 在线矿机数、总算力
```
