import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  adminUserStatusMeta,
  buildMergeConfirmationText,
  mergePreviewSummary,
  serializeAuditFilters,
  serializeSystemEmailPayload
} from '../src/pages/Admin/admin-model.js';

test('maps admin user statuses to labels and colors', () => {
  assert.deepEqual(adminUserStatusMeta('pending_email'), { label: '待验证邮箱', color: 'gold' });
  assert.deepEqual(adminUserStatusMeta('pending_review'), { label: '待管理员审核', color: 'blue' });
  assert.deepEqual(adminUserStatusMeta('active'), { label: '正常', color: 'green' });
  assert.deepEqual(adminUserStatusMeta('disabled'), { label: '已禁用', color: 'red' });
});

test('summarizes merge preview counts and confirmation text', () => {
  const preview = {
    sourceUser: { username: 'admin' },
    targetUser: { username: 'chendeben' },
    confirmationText: 'MERGE admin INTO chendeben',
    selectedCounts: {
      domains: 3,
      dnsCredentials: 2,
      apiTokens: 1,
      sendEvents: 9,
      smtpCredential: 0
    }
  };

  assert.equal(buildMergeConfirmationText(preview.sourceUser, preview.targetUser), preview.confirmationText);
  assert.deepEqual(mergePreviewSummary(preview), [
    { key: 'domains', label: '域名', count: 3 },
    { key: 'dnsCredentials', label: 'DNS 凭据', count: 2 },
    { key: 'apiTokens', label: 'API Token', count: 1 },
    { key: 'sendEvents', label: '发送记录', count: 9 },
    { key: 'smtpCredential', label: 'SMTP 凭据', count: 0 }
  ]);
});

test('serializes system email payload without blank password', () => {
  assert.deepEqual(serializeSystemEmailPayload({
    host: 'smtp.example.com',
    port: '587',
    secure: true,
    username: 'mailer',
    password: '   ',
    fromEmail: 'notify@example.com'
  }), {
    host: 'smtp.example.com',
    port: 587,
    secure: true,
    username: 'mailer',
    fromEmail: 'notify@example.com'
  });
});

test('serializes audit filters to query params', () => {
  assert.equal(serializeAuditFilters({
    actorUserId: 1,
    targetUserId: '',
    action: 'admin.user_merge',
    from: '2026-07-08',
    to: undefined
  }), 'actorUserId=1&action=admin.user_merge&from=2026-07-08');
});
