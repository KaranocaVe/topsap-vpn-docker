# TopSAP VPN Docker

用 Docker 封装 TopSAP Linux 客户端，将 VPN 连接和 SOCKS5 代理限制在容器内。本机只看到回环地址上的 SOCKS5 代理端口，其他应用可按需使用该代理访问 VPN 内网。

项目地址：[`KaranocaVe/topsap-vpn-docker`](https://github.com/KaranocaVe/topsap-vpn-docker)

默认镜像：`ghcr.io/karanocave/topsap-vpn-docker:latest`

发布镜像的平台：`linux/amd64`、`linux/arm64`。macOS 和 Windows 使用 Docker Linux VM 运行，不提供原生 macOS/Windows 镜像；当前不支持 `loong64`。

这个仓库是 TopSAP 的容器包装器，不是 TopSAP 官方项目，也不代表 Topsec。包装器源码使用 MIT；TopSAP 客户端及其他第三方组件仍按各自条款使用，见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

## 工作方式

```text
本机应用（curl、浏览器、客户端）
        │ SOCKS5
        ▼
127.0.0.1:1080 → MicroSocks（UID 65534）→ tun0 → 内网 TCP 目标
                                      │
                                      └─ supervisor → TopSAP 后端、Xvfb/Electron、VPN 登录和 TOTP
```

- 容器内负责 TopSAP、TUN、路由、DNS 和 SOCKS5；宿主机不安装 TopSAP。
- 代理只发布到宿主机回环地址。防火墙限制代理新建连接只能走 TUN，隧道消失时不会回落到普通出口。
- root 文件系统只读；运行时的厂商文件、配置和浏览器 profile 放在 tmpfs。宿主机只绑定一个用于切换 bootstrap DNS/VPN DNS 的 resolver 文件。
- 没有 host network、特权容器、Docker socket 或宿主家目录挂载。厂商后端仍以容器 root 运行并需要 `NET_ADMIN`，因此防火墙不构成对已被攻破的容器 root 的安全边界。
- supervisor 检查必需进程、TUN 路由和真实 SOCKS 连接；失败时清理进程组和 TUN，并以 10–120 秒退避重新登录。连续登录失败达到限制后进入 `needs_attention`，需要人工修正配置并重启。

## 快速开始

需要 Docker Engine 或 Docker Desktop，以及 Compose v2。Docker Desktop 用户应确认 Docker Desktop 的 Linux VM 正在运行。镜像和本地构建都支持 `amd64` 与 `arm64`。

```sh
git clone https://github.com/KaranocaVe/topsap-vpn-docker.git
cd topsap-vpn-docker
cp .env.example .env
chmod 600 .env
# 编辑 .env，至少填写 VPN_HOST、VPN_ACCOUNT、VPN_PASSWD、VPN_TOTP_SECRET、VPN_DNS、HEALTHCHECK_HOST、HEALTHCHECK_PORT
$EDITOR .env

./start.sh                         # 使用 GHCR latest；创建 resolver 并等待 healthy
```

示例配置使用 `vpn.example.com`；健康检查目标必须替换成管理员提供且经 VPN 可达的 TCP 主机和端口，其中 `HEALTHCHECK_HOST` 使用目标 IP，`HEALTHCHECK_PORT` 使用目标 TCP 端口。DNS 示例与 `.env.example` 保持为 `10.0.0.53`。这些值都必须替换成适合当前网络的值。`VPN_TOTP_SECRET` 是已绑定认证器的 Base32 密钥；实现固定使用 SHA1、6 位、30 秒周期。`.env` 是数据文件，不会被 shell `source`，不支持变量插值或命令执行；不要提交真实 `.env`。

启动前 `start.sh` 会创建 `runtime/resolv.conf`。服务启动后会等待 Docker healthcheck 通过；若超时，先看日志：

```sh
python3 manage.py status
python3 manage.py check       # 检查 TUN 路由和经 SOCKS 到 HEALTHCHECK_HOST 的实际连接
python3 manage.py logs
```

服务 healthy 后，可直接让支持 SOCKS5 的客户端使用回环端口。例如：

```sh
curl --socks5-hostname 127.0.0.1:1080 https://target.example/
```

将 `target.example` 换成经 VPN 可达的目标；`--socks5-hostname` 会让目标域名通过 SOCKS5 解析。

本地源码构建：

```sh
./start.sh --build
# 或
python3 manage.py build
```

## 配置

从 `.env.example` 开始。值包含空格或 `#` 时用引号包围；每个键只能出现一次。

| 设置 | 默认/示例 | 说明 |
| --- | --- | --- |
| `TOPSAP_IMAGE` | `ghcr.io/karanocave/topsap-vpn-docker:latest` | Compose 使用的镜像。可在 `.env` 中改为版本标签或 `@sha256:...` digest 固定版本。 |
| `VPN_HOST` | `vpn.example.com:443` | VPN 网关。 |
| `VPN_ACCOUNT` / `VPN_PASSWD` | — | VPN 账户和密码，只经 Docker secret 文件传入容器。 |
| `VPN_TOTP_SECRET` | — | Base32 TOTP 密钥；SHA1、6 位、30 秒。 |
| `VPN_DNS` | `10.0.0.53` | 运行期 DNS，必须能经 TUN 到达；不会回退到 Docker DNS 或公网 DNS。启动阶段解析网关时才使用 Docker bootstrap DNS。 |
| `VPN_MTU` | `1280` | TUN MTU，允许范围 1280–1500；链路较敏感时可使用更保守的 MTU。 |
| `LOGIN_TIMEOUT` | `120` | 单次登录等待隧道的秒数。 |
| `LOGIN_FAILURE_LIMIT` | `3` | 连续登录失败（含页面、网络和隧道超时）后停止尝试并进入 `needs_attention`。 |
| `SOCKS_PORT` | `1080` | 仅绑定宿主机 `127.0.0.1`。 |
| `HEALTHCHECK_HOST` / `HEALTHCHECK_PORT` | `10.0.0.10` / `443` | 必须经 VPN 到达的通用 TCP 探测目标；只检查 TCP 连接，不依赖特定协议或服务 banner。将主机替换为管理员提供的目标 IP。 |
| `DEBUG_DESKTOP` | `0` | 设为 `1` 后临时发布回环地址上的 noVNC `6080`，只用于排障。入口无额外认证，用完改回 `0` 并重启。 |

凭证文件挂载到容器 `/run/secrets/topsap.env`，不写入镜像、Docker 环境变量或进程参数。拥有 Docker 管理权限的宿主用户仍可访问容器数据；请按本机权限模型保护 Docker。

## 管理命令

所有命令都在仓库目录运行，并读取当前 `.env`：

| 命令 | 作用 |
| --- | --- |
| `python3 manage.py up` | 启动服务并等待 healthy；`up --build` 先本地构建。 |
| `python3 manage.py build` | 按当前 `packages.lock.json` 构建本地镜像。 |
| `python3 manage.py pull` | 拉取 `TOPSAP_IMAGE` 指定的镜像。 |
| `python3 manage.py update` | 手工拉取镜像、重新创建服务并等待 healthy。不会在宿主机后台定时运行。 |
| `python3 manage.py down` | 停止并删除 Compose 服务和网络。 |
| `python3 manage.py restart` | 强制重建容器、重新读取 `.env` 并等待 healthy。 |
| `python3 manage.py status` | 查看容器状态和 health 状态。 |
| `python3 manage.py logs` | 跟随最近 100 行服务日志，Ctrl-C 退出。 |
| `python3 manage.py check` | 在容器内验证 TUN 路由和经 SOCKS 到探测目标的实际连接。 |

管理 CLI 仅提供上表中的九个子命令，以及 `--build` 和 `--timeout SECONDS` 选项。`up` 支持附加 `--build` 在启动前构建镜像；需要延长等待时间时可传 `--timeout`。`restart: unless-stopped` 只负责 Docker 自身重启后的服务恢复；执行 `down` 或手工停止后不会替你重新启动。

## 客户端示例

容器只提供 SOCKS5 代理，不生成客户端配置。需要通过 SSH 访问 VPN 内网目标时，可手工在自己的 `~/.ssh/config` 中加入以下片段：

```sshconfig
Host vpn-server
    HostName 10.0.0.10
    User your-user
    ProxyCommand nc -X 5 -x 127.0.0.1:1080 %h %p
```

将 `vpn-server`、`10.0.0.10` 和 `your-user` 换成自己的目标与账户后，运行 `ssh vpn-server`。SSH 沿用本机密钥与 `known_hosts`。Linux 和 macOS 的 `nc` 参数可能不同，请先用 `nc -h` 确认本机实现支持 `-X 5` 与 `-x`。

## 构建、上游锁定与发布

Dockerfile 不再依赖仓库中的 vendor 安装包。构建阶段执行 `scripts/upstream.py download`，从官方 `https://app.topsec.com.cn/` 下载 `packages.lock.json` 中 `$TARGETARCH`（`amd64` 或 `arm64`）的 URL，并校验：

- HTTPS、官方域名、无查询参数和无跨域重定向；
- 下载大小上限、SHA256 和文件完整性；
- Debian 包名、架构和版本与锁文件一致；
- 只提取厂商 payload，不运行厂商安装/卸载脚本。
- 清理原包中不必要的 group/world-writable 与 setuid/setgid 权限。

SHA256 是从官方 HTTPS 下载内容计算并锁定的完整性校验，不是厂商签名或真实性证明。

手工刷新锁文件：

```sh
python3 scripts/upstream.py update --output packages.lock.json
git diff -- packages.lock.json
python3 manage.py build
```

`update` 会重新读取官网目录、分别下载并计算 `amd64`/`arm64` 的 SHA256；拒绝版本回退，并省略时间戳以避免无内容变化的每日提交。锁文件应和源码一起审阅。

GitHub Actions 在直连官网超时后，会从 GeoNode 和 Proxifly 的公开中国代理列表中筛选 HTTP CONNECT 出口。所有官网连接仍验证 HTTPS 证书和官方域名，锁定构建仍逐字节校验 SHA256；代理不进入运行镜像，也不接触用户的 VPN、TOTP 或其他运行时凭证。下载中断或哈希不符会丢弃临时文件并切换出口，全部失败则终止任务。公开代理随时可能失效，流程无法保证每日都能取得可用出口。

本地构建默认直连；需要相同备用机制时可运行：

```sh
docker build --build-arg TOPSAP_PUBLIC_PROXY=1 -t topsap-vpn:local .
python3 scripts/upstream.py update --public-proxy
```

GitHub Actions 的边界如下：

- 定时上游任务检测官网更新；锁文件变化时自动提交，并调用发布流程。
- 发布流程使用原生 `amd64` 与 `arm64` runner 构建，并在没有 VPN 凭证的环境中执行包、依赖和启动组件 smoke；分别推送架构 digest，再合并为 GHCR manifest。
- GHCR 标签包括 `latest`、`sha-<完整 commit SHA>` 和 `lock-<packages.lock.json SHA256 前 16 位>`；其中 commit 和锁文件标签用于追溯构建输入。
- Pull request 只构建和 smoke，不推送镜像。
- CI 验证的是包、依赖和启动组件，不验证任何用户的 VPN 登录、账户、TOTP 或内网目标。

全自动上游发布不等于本机无人值守更新。运行中的主机不会自动切换镜像；需要人工执行 `python3 manage.py update` 拉取并重新创建服务。若锁文件或源码发生变化，使用 `python3 manage.py up --build` 或 `./start.sh --build`。

## 故障排查

1. **启动超时或容器退出**：确认 Docker 正常运行、`.env` 已从示例创建且权限为 `0600`；执行 `python3 manage.py logs`。页面不可用、网络失败和等待 TUN 超时都会计入登录失败次数。
2. **状态为 `needs_attention`**：修正网关、账户、密码或 TOTP 后执行 `python3 manage.py restart`。达到 `LOGIN_FAILURE_LIMIT` 后服务会停止继续提交错误登录。
3. **health 不通过**：执行 `python3 manage.py check`。它同时检查目标是否由 TUN 路由，以及 SOCKS 到目标的真实 TCP 连接。确认 `HEALTHCHECK_HOST` 和 `HEALTHCHECK_PORT` 是经 VPN 可达的目标与端口。
4. **IP 可达但域名失败**：检查 `VPN_DNS` 是否是经 TUN 可达的 DNS。运行期不会使用 Docker DNS 或公网 DNS 回退。
5. **SOCKS 代理连接失败**：检查客户端是否连接 `127.0.0.1:1080`，并用 `python3 manage.py status` 确认代理已 healthy；支持 SOCKS5 的客户端可用 `curl --socks5-hostname 127.0.0.1:1080 https://target.example/` 验证。
6. **需要查看桌面**：临时设置 `DEBUG_DESKTOP=1` 并执行 `restart`，访问 `http://127.0.0.1:6080/vnc.html?autoconnect=1`；完成后恢复为 `0` 并再次重启。

提交 Issue 或日志片段前，请删除账户、密码、TOTP、网关凭证、内网地址和主机指纹。

## 许可证

仓库包装器源码采用 [MIT License](LICENSE)。TopSAP 专有客户端、Debian/Alpine 基础镜像及运行时依赖不因本仓库的 MIT 许可而获得再授权；第三方来源和权利见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
