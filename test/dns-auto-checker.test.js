import assert from 'node:assert/strict';
import { test } from 'node:test';
import { runDnsAutoCheck, shouldAutoCheckDomain } from '../src/dns-auto-checker.js';

test('dns auto-check selects unchecked, stale, and unverified domains only', () => {
  const now = new Date('2026-07-09T03:00:00.000Z');

  assert.equal(shouldAutoCheckDomain({ status: {} }, { now, minIntervalMs: 60000 }), true);
  assert.equal(shouldAutoCheckDomain({
    status: { verified: false, checkedAt: '2026-07-09T02:58:30.000Z' }
  }, { now, minIntervalMs: 60000 }), true);
  assert.equal(shouldAutoCheckDomain({
    status: { verified: false, checkedAt: '2026-07-09T02:59:30.000Z' }
  }, { now, minIntervalMs: 60000 }), false);
  assert.equal(shouldAutoCheckDomain({
    status: { verified: true, checkedAt: '2026-07-01T00:00:00.000Z' }
  }, { now, minIntervalMs: 60000 }), false);
});

test('dns auto-check refreshes eligible domains and continues after failures', async () => {
  const saved = [];
  const warnings = [];
  const domains = [
    { id: 1, userId: 10, domain: 'ready.example', status: {} },
    {
      id: 2,
      userId: 10,
      domain: 'fresh.example',
      status: { verified: false, checkedAt: '2026-07-09T02:59:30.000Z' }
    },
    { id: 3, userId: 11, domain: 'broken.example', status: {} }
  ];

  const result = await runDnsAutoCheck({
    listDomains: () => domains,
    buildGuide: async (domain) => {
      if (domain.domain === 'broken.example') throw new Error('DNS timeout');
      return { checkedAt: '2026-07-09T03:00:00.000Z', verified: true, records: [] };
    },
    saveStatus: (id, userId, status) => saved.push({ id, userId, status }),
    logger: { warn: (message) => warnings.push(message) },
    now: () => new Date('2026-07-09T03:00:00.000Z'),
    minIntervalMs: 60000,
    limit: 10
  });

  assert.deepEqual(saved.map((item) => item.id), [1]);
  assert.equal(saved[0].userId, 10);
  assert.equal(saved[0].status.verified, true);
  assert.equal(result.checked, 1);
  assert.equal(result.failed, 1);
  assert.equal(result.skipped, 1);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /broken\.example/);
});
