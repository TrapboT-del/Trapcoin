# TRAP 主网部署指南

本文说明如何在 Linux 服务器上部署 TRAP 节点（`trapcoind`）和 solo 挖矿矿池（ckpool），并让 ASIC 矿机接入挖矿。
流程已于 2026-09-28 在测试环境完整彩排：Bitaxe 矿机经 ckpool 挖到第 2125 块，
期间验证了区块同步、挖矿奖励成熟、钱包转账，以及第 2016 块难度从 1 调整到 4。

## 架构

```
ASIC 矿机 ──Stratum:3333──> ckpool（solo） ──RPC:4199──> trapcoind ──P2P:4200──> 其他 TRAP 节点
```

| 端口 | 用途 | 是否对外开放 |
|---|---|---|
| 4200 | P2P，节点之间通信 | 开放 |
| 4199 | RPC，仅供本机的 `trapcoin-cli` 和 ckpool 使用 | **绝不开放** |
| 3333 | Stratum，矿机连接矿池 | 只对矿机所在网络开放 |

## 1. 准备服务器

- 系统：Ubuntu 22.04 / 24.04
- 起步配置：2 核、4 GB 内存、50 GB 硬盘
- 建议至少 2 台位于不同地区的公网服务器，互相 `addnode`，避免单点故障

```bash
sudo apt install -y build-essential cmake pkgconf python3 git \
    libevent-dev libboost-dev libsqlite3-dev \
    autoconf automake libtool yasm
sudo useradd --system --create-home --shell /usr/sbin/nologin trap
```

## 2. 编译安装 trapcoind

```bash
git clone https://github.com/TrapboT-del/Trapcoin.git
cd Trapcoin
cmake -B build -DBUILD_TESTS=OFF
cmake --build build -j"$(nproc)"
sudo cmake --install build          # 安装到 /usr/local/bin
```

## 3. 配置 trapcoind

```bash
sudo mkdir -p /etc/trap
sudo cp contrib/init/trap.conf.example /etc/trap/trap.conf
python3 share/rpcauth/rpcauth.py trapmine
```

把 `rpcauth.py` 打印出的 `rpcauth=...` 一行替换到 `/etc/trap/trap.conf` 里，**记下它打印的密码**，第 5 步要用。
如果有其他 TRAP 节点，把它们写成 `addnode=IP:4200`。

```bash
sudo cp contrib/init/trapcoind.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now trapcoind
sudo -u trap trapcoin-cli -datadir=/var/lib/trapcoind -conf=/etc/trap/trap.conf getblockchaininfo
```

## 4. 防火墙

```bash
sudo ufw allow 4200/tcp                            # P2P
sudo ufw allow from 矿机所在网段 to any port 3333 proto tcp   # Stratum
sudo ufw enable
```

## 5. 编译安装 ckpool

ckpool 需要一个 TRAP 专用补丁（见下文"已知问题"），用仓库里的脚本编译：

```bash
contrib/ckpool/build-ckpool.sh ~/ckpool
sudo install ~/ckpool/src/ckpool /usr/local/bin/ckpool
sudo cp contrib/ckpool/ckpool.conf.example /etc/trap/ckpool.conf
```

编辑 `/etc/trap/ckpool.conf`：
- `pass`：第 3 步 `rpcauth.py` 打印的密码
- `btcaddress`：一个你控制的 TRAP 地址（`trap1...`）

然后启动：

```bash
sudo chown root:trap /etc/trap/ckpool.conf && sudo chmod 640 /etc/trap/ckpool.conf
sudo cp contrib/init/trap-ckpool.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now trap-ckpool
```

## 6. 挖出第一个区块（仅首次上线需要）

主网节点只有同时满足以下两个条件，才会给矿池出挖矿任务：

1. **至少连着一个其他节点**，否则报 `Trap Core is not connected!`。
   上线时至少再开一台节点，并互相 `addnode`。
2. **不处于初始区块同步（IBD）状态**，否则报 `Trap Core is in initial sync`。
   链顶超过 24 小时没有新块，节点就会认为自己在同步中。创世区块是 2026-09-27 的，
   所以挖第一个块前，要在 `trap.conf` 里取消注释 `maxtipage=315360000` 并重启 trapcoind。
   链开始正常出块后删掉这一行即可。

## 7. 矿机配置（以 Bitaxe / AxeOS 为例）

| 设置项 | 值 |
|---|---|
| Stratum Host | 服务器 IP（不要带 `stratum+tcp://` 前缀） |
| Stratum Port | `3333` |
| Stratum User | `你的TRAP地址.矿机名`，例如 `trap1q....bitaxe1` |
| Stratum Password | `x` |
| Suggested Difficulty | 链的难度很低时设为 `1`（见下文） |
| Fallback 矿池 | 留空，或填同一地址 |

solo 模式下，挖到的区块奖励全部归用户名里的 TRAP 地址。

## 已知问题与经验（来自彩排）

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
- **`inconclusive`**：ckpool 日志里的 `SUBMIT BLOCK RETURNED: inconclusive` 表示过期份额产生的孤块，属正常现象；
  `bad-*` 开头的才是真正的拒绝。
- **虚拟机网络**：在 VMware NAT 虚拟机里测试时，需要在"虚拟网络编辑器"里添加端口转发
  （主机 3333 → 虚拟机 3333），并在 Windows 防火墙放行 3333，矿机填宿主机的局域网 IP。

## 日常运维

```bash
sudo systemctl status trapcoind trap-ckpool
sudo journalctl -u trap-ckpool -f
sudo -u trap trapcoin-cli -datadir=/var/lib/trapcoind -conf=/etc/trap/trap.conf getmininginfo
sudo tail -f /var/lib/trap-ckpool/logs/ckpool.log
```
