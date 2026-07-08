# MailHub

MailHub 是一个 Docker 化的多用户发信控制面板、SMTP Submission 服务和发送 API。它面向需要自托管出站邮件能力的团队，提供域名验证、DKIM 签名、DNS 配置提示、SMTP 凭据和 API Token 管理。

## 功能

- 多用户账号体系，隔离域名、SMTP 凭据、DNS API 凭据、API Token 和发送记录。
- 为发信域名生成验证 TXT、DKIM、SPF、DMARC、发信主机 A 记录和 PTR 检查提示。
- 支持 Cloudflare、阿里云 DNS、腾讯云 DNSPod API 的基础 DNS 写入。
- 检查公网 DNS 中的 SPF、DKIM、DMARC、PTR 和发信主机 A 记录状态。
- 通过内部 Postfix 出站队列发送邮件，并按发件域名添加 DKIM 签名。
- 提供 SMTP Submission 和 HTTP 发送 API。
- 内置 React + Ant Design 管理界面。

## 技术栈

- Node.js ESM，要求 Node.js `>=24.0.0`
- SQLite 持久化
- React、Vite、Ant Design
- Docker Compose + Postfix
- Node 内置 `node:test`

## 快速开始

```bash
cp .env.example .env
npm install
npm test
npm run build
docker compose up -d --build
docker compose logs -f app postfix
```

默认管理面板通过 `APP_PORT` 暴露到宿主机 `127.0.0.1:3025`。生产环境建议使用 Nginx、Caddy 或其他反向代理提供 HTTPS。

首次启动前务必修改 `.env` 中的默认管理员密码、`SESSION_SECRET`、SMTP 凭据和域名/IP 配置。

## 配置

以 `.env.example` 为模板创建 `.env`。常用配置包括：

- `APP_BASE_URL`：管理面板和发送 API 的公网访问地址。
- `MAIL_HOSTNAME`：出站邮件 HELO、Postfix `myhostname` 和 DNS 指南中的发信主机名。
- `SENDING_IP`：发信服务器公网 IP。
- `SESSION_SECRET`：会话和服务端加密使用的随机密钥，生产环境必须使用强随机值。
- `SUBMISSION_HOST`、`SUBMISSION_PORTS`：SMTP Submission 对外连接信息。
- `SUBMISSION_TLS_CERT`、`SUBMISSION_TLS_KEY`：TLS 证书路径。证书文件应放在本地 `certs/`，不要提交到 Git。
- `DEFAULT_SPF_MECHANISMS`：需要保留的第三方 SPF include，例如事务邮件服务商。
- `SEND_REQUIRES_VERIFIED`：是否要求域名 DNS 验证通过后才能发信。

## SMTP 发信

MailHub 提供公网 SMTP Submission。所有发信端口都需要 SMTP AUTH，未认证请求不会转发邮件，避免开放中继。

```txt
Host: 由 SUBMISSION_HOST 配置，例如 smtp.mailhub.example.com
Port 25:   SMTP + STARTTLS + AUTH
Port 587:  SMTP Submission + STARTTLS + AUTH
Port 465:  SMTPS implicit TLS + AUTH
Port 2525: SMTP + STARTTLS + AUTH
Username: 用户在网页“SMTP 凭据”中配置
Password: 用户在网页“SMTP 凭据”中配置
```

SMTP 密码会同时保存哈希和服务端加密密文：哈希用于认证，加密密文用于用户本人在网页复制。旧数据如果只有哈希，无法反解，需要用户重新设置一次密码后才能复制。

## 发送 API

每个用户可以在面板生成自己的发送 API Token。Token 只在创建时完整显示，之后列表只显示前缀。

```bash
curl -X POST https://mailhub.example.com/api/send \
  -H "Authorization: Bearer <USER_API_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "from": "noreply@example.com",
    "to": "user@example.net",
    "subject": "Hello from MailHub",
    "text": "Signed with DKIM and queued by MailHub."
  }'
```

发送时会校验 `From` 所属域名必须归当前 Token 所属用户所有。`.env` 中的 `API_TOKEN` 仅作为旧版 admin 兼容发送 token，新用户应使用网页生成的用户级 Token。

## DNS API 一键配置

用户可在网页“DNS API”中保存以下服务商凭据：

- Cloudflare：API Token，建议只授予目标 Zone 的 DNS Edit 权限；可选 Zone ID。
- 阿里云 DNS：AccessKeyId 和 AccessKeySecret。
- 腾讯云 DNSPod：SecretId 和 SecretKey。

域名绑定 DNS 凭据后，点击“一键配置 DNS”会写入或更新验证 TXT、DKIM TXT、SPF TXT、DMARC TXT 和发信主机 A 记录。PTR 反向解析只检测和提示，通常必须在云服务器或 IP 服务商控制台配置。

## 部署

生产环境建议：

1. 将仓库部署到服务器目录，例如 `/opt/mailhub`。
2. 基于 `.env.example` 创建 `.env`，填写真实域名、IP、证书路径和强随机密钥。
3. 将 TLS 证书放在本地 `certs/` 目录，确保私钥不会进入 Git。
4. 运行 `docker compose up -d --build`。
5. 使用反向代理把 HTTPS 流量转发到 `127.0.0.1:${APP_PORT}`。
6. 在云防火墙和系统防火墙中放行需要的 SMTP 端口。

可选的远程部署脚本需要显式提供目标服务器和目录：

```bash
MAILHUB_DEPLOY_REMOTE=deploy@example.com \
MAILHUB_DEPLOY_DIR=/opt/mailhub \
MAILHUB_DEPLOY_BRANCH=main \
npm run deploy:remote
```

脚本会要求本地 HEAD 已推送到对应远端分支，然后在目标目录执行 `git pull --ff-only` 和 `docker compose up -d --build`。如果目标工作区存在未提交变更，脚本会停止；确认可暂存远端工作区时，可显式设置 `MAILHUB_DEPLOY_STASH_REMOTE=1`。

## 测试

```bash
npm test
npm run build
```

测试覆盖数据库迁移、多用户隔离、SMTP 凭据、API Token、DNS 服务商逻辑、DKIM、投递日志解析和前端纯逻辑模型。

## 安全清单

- 不要提交 `.env`、SQLite 数据库、API Token、SMTP 密码、DNS API 密钥、证书私钥或真实生产证书。
- 替换默认管理员凭据，设置足够长的 `SESSION_SECRET`。
- 生产发信前确认 SPF、DKIM、DMARC、PTR 和发信主机 A 记录。
- 确认服务器出站 25 端口没有被云厂商拦截。
- 确认入站 `25/465/587/2525` 已在云防火墙和系统防火墙放行。
- 新 IP 先小流量预热，避免突然大批量发送。
- 遵守适用法律、服务商政策和收件人同意要求；不要使用 MailHub 发送垃圾邮件。

## 贡献

欢迎提交 issue 和 pull request。开始前请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)、[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) 和 [SECURITY.md](SECURITY.md)。

## 许可证

MailHub 使用 MIT License。详见 [LICENSE](LICENSE)。
