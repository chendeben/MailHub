# Contributing

Thank you for contributing to MailHub. The project prefers focused, verifiable, maintainable changes.

## Development Setup

```bash
npm install
npm test
npm run build
```

Use a Node.js version that satisfies the `>=24.0.0` requirement in `package.json`.

## Workflow

- Search existing issues before opening a new one.
- Keep pull requests focused on one topic. Avoid unrelated formatting or refactoring.
- Add or update tests when behavior changes.
- Include screenshots, request examples, or verification steps when UI or API behavior changes.
- Do not commit `.env`, databases, certificates, private keys, API tokens, SMTP passwords, or real production configuration.

## Code Style

- Use ES modules.
- Use two-space indentation and semicolons for JavaScript and TypeScript.
- Prefer `const`; use `let` only when reassignment is required.
- Keep files focused on a single responsibility and prefer direct implementations.
- Keep comments short and reserve them for non-obvious business constraints or security reasoning.

## Pull Request Checklist

- [ ] `npm test` has been run.
- [ ] `npm run build` has been run.
- [ ] `git diff` has been reviewed for personal information and secrets.
- [ ] Documentation has been updated for behavior changes.
- [ ] New configuration keys have been added to `.env.example`.

## Commit Messages

Conventional-Commits-style prefixes are recommended:

- `feat:` new features
- `fix:` bug fixes
- `docs:` documentation
- `test:` tests
- `chore:` maintenance

Keep the subject concise and focused on one change.
