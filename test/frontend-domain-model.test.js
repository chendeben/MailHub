import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  buildDomainHealth,
  getRecordStatusMeta,
  getRequiredDnsRecords
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
        record('ptr', 'ok'),
        record('optional-mta-sts', 'ok')
      ]
    }
  };

  assert.deepEqual(getRequiredDnsRecords(domain).map((item) => item.key), [
    'verification',
    'dkim',
    'spf',
    'dmarc',
    'sender-a',
    'ptr'
  ]);

  assert.deepEqual(buildDomainHealth(domain), {
    status: 'error',
    label: '需要处理',
    passed: 3,
    total: 6,
    percent: 50,
    dnsIssues: 2,
    checkedAt: '2026-07-08T10:30:00.000Z'
  });
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
