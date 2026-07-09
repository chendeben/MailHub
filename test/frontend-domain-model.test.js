import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  buildDnsApplyFeedback,
  buildDomainHealth,
  getDnsCurrentValues,
  getRecordStatusMeta,
  getRequiredDnsRecords,
  getVisibleDnsRecords
} from '../src/frontend/domain-model.js';

test('maps DNS record states to stable UI status metadata', () => {
  assert.deepEqual(getRecordStatusMeta({ status: 'ok' }), {
    key: 'success',
    label: '已通过',
    color: 'success'
  });
  assert.deepEqual(getRecordStatusMeta({ status: 'pending' }), {
    key: 'pending',
    label: '等待生效',
    color: 'warning'
  });
  assert.deepEqual(getRecordStatusMeta({ status: 'warn' }), {
    key: 'error',
    label: '配置错误',
    color: 'error'
  });
  assert.deepEqual(getRecordStatusMeta({ status: 'missing' }), {
    key: 'idle',
    label: '未配置',
    color: 'default'
  });
});

test('builds domain health from required DNS records only', () => {
  const domain = {
    domain: 'example.com',
    senderHost: 'mail.example.com',
    sendingIp: '203.0.113.10',
    status: {
      checkedAt: '2026-07-08T10:30:00.000Z',
      records: [
        record('verification', 'ok'),
        record('dkim', 'ok'),
        record('spf', 'pending'),
        record('dmarc', 'warn'),
        record('sender-a', 'missing'),
        record('ptr', 'missing'),
        record('optional-mta-sts', 'ok')
      ]
    }
  };

  assert.deepEqual(getRequiredDnsRecords(domain).map((item) => item.key), [
    'verification',
    'dkim',
    'spf',
    'dmarc',
    'sender-a'
  ]);

  assert.deepEqual(buildDomainHealth(domain), {
    status: 'error',
    label: '需要处理',
    passed: 2,
    total: 5,
    percent: 40,
    dnsIssues: 2,
    checkedAt: '2026-07-08T10:30:00.000Z'
  });
});

test('builds warning feedback for partial DNS apply failures', () => {
  const feedback = buildDnsApplyFeedback({
    ok: false,
    results: [
      { key: 'verification', type: 'TXT', host: '_mailhub.notify.example.com', ok: true },
      {
        key: 'dkim',
        type: 'TXT',
        host: 'mh._domainkey.notify.example.com',
        ok: false,
        error: 'domain not found'
      }
    ]
  }, {
    completed: 'DNS 写入请求已完成',
    partial: 'DNS 写入部分失败'
  });

  assert.deepEqual(feedback, {
    type: 'warning',
    message: 'DNS 写入部分失败：domain not found'
  });
});

test('normalizes DNS current values with legacy successful record fallback only', () => {
  assert.deepEqual(getDnsCurrentValues({ current: ['one', 'two'], value: 'target', status: 'ok' }), ['one', 'two']);
  assert.deepEqual(getDnsCurrentValues({ current: 'one', value: 'target', status: 'ok' }), ['one']);
  assert.deepEqual(getDnsCurrentValues({ value: 'target', status: 'ok' }), ['target']);
  assert.deepEqual(getDnsCurrentValues({ value: 'target', status: 'missing' }), []);
});

test('hides legacy PTR records from per-domain DNS record lists', () => {
  assert.deepEqual(getVisibleDnsRecords([
    record('ptr', 'ok'),
    record('spf', 'ok'),
    record('verification', 'ok'),
    record('unknown', 'ok')
  ]).map((item) => item.key), ['verification', 'spf']);
});

function record(key, status) {
  return {
    key,
    label: key,
    type: 'TXT',
    host: `${key}.example.com`,
    value: 'value',
    status
  };
}
