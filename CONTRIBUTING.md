# Contributing

感谢你愿意参与 MailHub。这个项目优先接受聚焦、可验证、易维护的改动。

## 开发环境

```bash
npm install
npm test
npm run build
```

Node.js 版本需满足 `package.json` 中的 `>=24.0.0`。

## 工作方式

- 提交 issue 前先搜索是否已有相同问题。
- PR 尽量保持单一主题，避免混入无关格式化或重构。
- 修改行为时补充或更新测试。
- 修改 UI 或 API 行为时，在 PR 中提供截图、请求示例或验证步骤。
- 不要提交 `.env`、数据库、证书、私钥、API Token、SMTP 密码或真实生产配置。

## 代码风格

- 使用 ES modules。
- JavaScript/TypeScript 使用两空格缩进和分号。
- 默认使用 `const`，仅在需要重新赋值时使用 `let`。
- 保持文件职责单一，优先选择直观实现。
- 注释保持简短，只解释不明显的业务约束或安全原因。

## Pull Request 检查清单

- [ ] 已运行 `npm test`。
- [ ] 已运行 `npm run build`。
- [ ] 已检查 `git diff`，确认没有个人信息或密钥。
- [ ] 文档已随行为变化更新。
- [ ] 新增配置项已同步 `.env.example`。

## Commit 信息

推荐使用类似 Conventional Commits 的前缀：

- `feat:` 新功能
- `fix:` 修复
- `docs:` 文档
- `test:` 测试
- `chore:` 维护

标题应简洁，并聚焦单一变更。
