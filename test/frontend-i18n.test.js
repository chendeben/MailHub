import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  DEFAULT_LOCALE,
  createTranslator,
  normalizeLocale,
  supportedLocales
} from '../src/frontend/i18n/index.js';

test('uses Chinese as the default locale and normalizes supported aliases', () => {
  assert.equal(DEFAULT_LOCALE, 'zh-CN');
  assert.deepEqual(supportedLocales, ['zh-CN', 'en-US']);
  assert.equal(normalizeLocale(), 'zh-CN');
  assert.equal(normalizeLocale('zh'), 'zh-CN');
  assert.equal(normalizeLocale('en'), 'en-US');
  assert.equal(normalizeLocale('fr-FR'), 'zh-CN');
});

test('translates known UI keys and falls back safely', () => {
  const zh = createTranslator('zh-CN');
  const en = createTranslator('en-US');

  assert.equal(zh('common.refresh'), '刷新');
  assert.equal(en('common.refresh'), 'Refresh');
  assert.equal(zh('auth.loginTitle'), '登录控制台');
  assert.equal(en('auth.loginTitle'), 'Sign in to console');
  assert.equal(zh('auth.forgotPassword'), '忘记密码？');
  assert.equal(en('auth.resetPasswordTitle'), 'Reset password');
  assert.equal(en('missing.translation.key'), 'missing.translation.key');
});

test('uses localized Chinese labels for the main navigation', () => {
  const zh = createTranslator('zh-CN');

  assert.equal(zh('nav.dashboard'), '仪表盘');
  assert.equal(zh('nav.domains'), '发信域名');
  assert.equal(zh('nav.dnsApi'), 'DNS API');
  assert.equal(zh('nav.smtp'), 'SMTP 凭据');
  assert.equal(zh('nav.tokens'), 'API Token');
  assert.equal(zh('nav.logs'), '发送记录');
  assert.equal(zh('nav.webhooks'), 'Webhooks');
  assert.equal(zh('nav.admin'), '管理员');
  assert.equal(zh('nav.settings'), '系统设置');
});

test('translates admin panel labels', () => {
  const zh = createTranslator('zh-CN');
  const en = createTranslator('en-US');

  assert.equal(zh('admin.title'), '管理员面板');
  assert.equal(zh('admin.users'), '用户');
  assert.equal(zh('admin.resources'), '资源');
  assert.equal(zh('admin.auditLogs'), '审计日志');
  assert.equal(en('admin.title'), 'Admin Panel');
});
