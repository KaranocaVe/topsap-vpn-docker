# 贡献指南

感谢贡献。这个仓库维护的是一个隔离的 TopSAP VPN 容器包装器；提交前请先确认改动属于包装器、构建锁定、生命周期管理或文档范围。

## 开始前

- 使用 Docker Engine 或 Docker Desktop Compose v2，并准备 `amd64` 或 `arm64` 环境。
- 从 `.env.example` 创建本地 `.env`；只填写自己的测试配置，保持文件权限为 `0600`。`.env`、TOTP、VPN 密码、主机指纹和真实内网地址不得进入 commit、Issue、日志截图或 CI。
- 仓库不需要提交 TopSAP vendor 安装包。构建阶段按 `packages.lock.json` 从官方站点下载并校验。

## 修改上游包锁文件

只用脚本刷新锁文件：

```sh
python3 scripts/upstream.py update --output packages.lock.json
git diff -- packages.lock.json
```

检查每个架构都有官方 HTTPS URL、版本、架构、文件大小和 SHA256；不要手工替换下载域名或绕过校验。上游任务会在锁文件有变化时提交更新并调用发布流程，因此不应把下载的 `.deb` 或临时文件加入仓库。

## 本地检查

提交前至少运行与改动相关的检查：

```sh
python3 -m unittest discover -s tests -p 'test_*.py'
python3 scripts/upstream.py --help
python3 manage.py --help
```

涉及 Dockerfile、Compose 或启动路径时，再执行镜像构建和无凭证 smoke。使用仓库提供的 smoke 脚本，不调用需要 `.env` 的 `manage.py up`：

```sh
docker build -t topsap-vpn:test . && .github/scripts/smoke-image.sh topsap-vpn:test
```

本地 VPN 登录需要有效的用户 `.env`，但不要把该配置带入自动化检查。测试应验证包、依赖、配置解析、启动组件、隔离和健康检查机制；不能把某个用户的 VPN 登录结果当作 CI 结论。

可选的实际 VPN 集成验证只应在有授权的测试网和本地凭证环境中进行：按 README 创建 `.env`，执行 `python3 manage.py up`、`python3 manage.py status`、`python3 manage.py check`，完成后执行 `python3 manage.py down`。这类验证不进入 CI，也不得上传凭证或真实内网信息。

## CI 与发布边界

- Pull request workflow 只构建 `amd64`/`arm64` 并运行 smoke，不登录 VPN，也不推送镜像。
- 发布 workflow 在原生 `amd64` 和 `arm64` runner 上构建，分别推送架构 digest，再合并 GHCR manifest。
- GHCR 标签包括 `latest`、`sha-<完整 commit SHA>` 和 `lock-<packages.lock.json SHA256 前 16 位>`。
- 定时上游 workflow 检查官方目录；锁文件有变化时自动 commit 并调用发布流程。
- CI 没有 VPN 凭证，因此只验证包、依赖和启动组件，不验证每个使用者的账户、TOTP 或内网目标。
- 发布完成不会自动更新贡献者或用户的本机 Docker 服务；本机更新仍由用户明确执行 `python3 manage.py update`。锁文件或源码改动需要 `python3 manage.py up --build`。

## 代码和安全边界

- 保持容器 rootfs 只读、最小 capability、TUN-only 代理出站和 UID 65534 的 MicroSocks 设计；需要改变边界时，请在 PR 中说明威胁模型和回归检查。
- 不要新增 host network、特权模式、Docker socket、宿主家目录挂载或未经说明的公网代理端口。
- 继续让 `.env` 作为数据解析，不执行 shell、不做变量插值，也不把敏感值放入镜像、Compose 环境、命令行或日志。
- 变更 TopSAP 登录流程、TUN 路由、DNS 或健康检查时，补充失败路径和恢复路径的测试说明。`needs_attention`、退避重连、TUN 清理和真实 SOCKS 探测是服务行为的一部分。

## Pull request

PR 描述请包含：

1. 改动目的和影响的架构边界；
2. 运行的本地命令及结果；
3. 是否改变镜像内容、上游锁文件、GHCR 发布或客户端使用示例；
4. 若涉及安全边界，说明验证方法和仍存在的限制。

请不要在 PR 中粘贴真实网关、账户、IP、TOTP、主机指纹或完整认证日志。提交文档或示例时统一使用 `vpn.example.com`、`10.0.0.10` 和占位账户。

## 第三方代码和许可

包装器源码适用 [MIT License](LICENSE)。TopSAP 客户端、Debian/Alpine 基础镜像和运行时软件包按各自许可证使用；提交涉及第三方文件或下载来源的改动时，请同步更新 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)，不要暗示本仓库拥有 TopSAP 的开源授权或官方关系。
