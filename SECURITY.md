# Security Policy

## Supported Versions

当前只维护默认分支的最新代码。发布正式版本后，本节会补充受支持版本范围。

## Reporting a Vulnerability

请不要在公开 issue 中披露未修复漏洞。

推荐通过 GitHub Security Advisories 私下报告安全问题。如果仓库尚未启用该功能，请通过维护者在仓库主页公布的安全联系方式报告。

报告中请尽量包含：

- 受影响的版本或提交。
- 复现步骤。
- 影响范围。
- 可行的缓解建议。

## Sensitive Data

MailHub 可能处理 SMTP 密码、API Token、DNS API 密钥和 TLS 私钥。请不要在 issue、PR、日志或截图中提交这些内容。

## Operational Guidance

- 生产环境必须替换默认管理员密码和 `SESSION_SECRET`。
- `.env`、SQLite 数据库、证书和私钥不应进入 Git。
- DNS API Token 应使用最小权限。
- 公网 SMTP 端口必须启用认证，避免开放中继。
- 使用本项目发送邮件时应遵守适用法律、服务商政策和收件人同意要求。
