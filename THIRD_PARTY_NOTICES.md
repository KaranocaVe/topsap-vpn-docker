# 第三方通知

本文件列出本项目包装、构建或运行时使用的主要第三方组件。它不是第三方许可证的替代品；镜像内的完整版权和许可证文本以各组件随附文件为准。

## TopSAP Linux 客户端

- **来源**：Topsec 官方下载站点 <https://app.topsec.com.cn/>。
- **用途**：容器内的厂商 VPN 客户端、后端和 Electron 文件。
- **权利**：TopSAP 是厂商专有软件，相关版权、商标和使用条件归 Topsec 或其许可方所有。它没有因为本仓库或 GHCR 镜像使用 MIT 而变成开源软件。
- **下载方式**：构建读取提交的 `packages.lock.json`，只从上述官方域名下载对应 `amd64`/`arm64` 包，校验 URL、版本、架构、大小和 SHA256 后提取 payload；仓库不提交 vendor 安装包。
- **再分发**：公开项目和公开镜像不构成 TopSAP 的再授权或官方背书。使用者必须自行确认账户、下载、部署和组织内分发符合厂商条款。

## Debian 和 Alpine

- 基础阶段使用 Debian `bookworm-slim`，证书阶段使用 Alpine `3.22`；镜像引用固定 digest。
- 运行时安装 Debian 官方仓库中的 `ca-certificates`、`iproute2`、`iptables`、`microsocks`、图形库、Xvfb、noVNC、websockify、Python 及其依赖。
- 这些发行版和软件包各自按其上游许可证提供。构建后的镜像中可在 `/usr/share/doc/<package>/copyright` 和相关许可证文件中查看具体文本；它们不受本仓库 MIT 许可重新覆盖。

## Python 和项目依赖

服务使用 Python 标准库，以及 Debian 提供的 `python3-websocket` 等运行时包。各包的许可证和版权信息随 Debian 包安装；本项目没有将其源码复制到仓库中。

## 其他说明

- 本仓库的 `app/`、`manage.py`、shell 脚本、Docker/Compose 配置和文档等包装器部分由 KaranocaVe 编写，适用 [MIT License](LICENSE)。
- `packages.lock.json` 只记录官方包的下载位置和完整性信息，不改变 TopSAP 的版权或许可范围。
- “TopSAP”及相关标识属于其权利人。本项目与 Topsec 没有官方隶属、赞助或认证关系。
