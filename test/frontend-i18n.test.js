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

test('nav group chrome strings exist', () => {
  const zh = createTranslator('zh-CN');
  const en = createTranslator('en-US');
  assert.equal(zh('nav.group.overview'), '概览');
  assert.equal(zh('nav.group.delivery'), '投递');
  assert.equal(zh('nav.group.system'), '系统');
  assert.equal(en('nav.group.overview'), 'Overview');
  assert.equal(en('nav.group.delivery'), 'Delivery');
  assert.equal(en('nav.group.system'), 'System');
});

test('translates admin panel labels', () => {
  const zh = createTranslator('zh-CN');
  const en = createTranslator('en-US');

  assert.equal(zh('admin.title'), '管理员面板');
  assert.equal(zh('admin.users'), '用户');
  assert.equal(zh('admin.resources'), '资源');
  assert.equal(zh('admin.auditLogs'), '审计日志');
  assert.equal(zh('settings.deliveryChecks'), '发信环境检查');
  assert.equal(en('admin.title'), 'Admin Panel');
  assert.equal(en('settings.deliveryChecks'), 'Sending Environment Checks');
});

test('translates smtp login credential labels separately from outbound relays', () => {
  const zh = createTranslator('zh-CN');
  const en = createTranslator('en-US');

  assert.equal(zh('smtp.loginCredentialsTitle'), '发信登录凭据');
  assert.equal(zh('smtpRelay.title'), '高级：外部 SMTP 出口');
  assert.equal(en('smtp.loginCredentialsTitle'), 'Sending login credentials');
  assert.equal(en('smtpRelay.title'), 'Advanced: external SMTP relays');
});

test('translates webhook page chrome strings', () => {
  const zh = createTranslator('zh-CN');
  const en = createTranslator('en-US');

  assert.equal(zh('webhooks.title'), 'Webhooks');
  assert.equal(zh('webhooks.secretCreatedWarning'), '完整密钥只会显示这一次。关闭后无法再次查看，请立即复制并保存到安全位置。');
  assert.equal(zh('webhooks.eventSent'), '已送达');
  assert.equal(zh('webhooks.replay'), '重放');
  assert.equal(zh('webhooks.domainOverrideHelp'), '若某域名对某一事件存在任何已启用的端点，则该事件不会再投递到账号级端点。');
  assert.equal(en('webhooks.title'), 'Webhooks');
  assert.equal(en('webhooks.create'), 'Create webhook');
  assert.equal(en('webhooks.statusDead'), 'Dead');
  assert.equal(en('actions.webhookCreated'), 'Webhook created');
});
