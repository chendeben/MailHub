import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import { test } from 'node:test';

import {
  claimWebhookDeliveries,
  createUser,
  createWebhook,
  enqueueWebhookDeliveries,
  initDatabase,
  listWebhookDeliveries
} from '../src/db.js';
import {
  assertSafeWebhookUrl,
  buildPinnedWebhookUrl,
  isBlockedIpAddress,
  processWebhookBatch,
  resolveSafeWebhookTarget,
  startWebhookWorker,
  stopWebhookWorker
} from '../src/webhook-dispatcher.js';
import { MAX_WEBHOOK_ATTEMPTS, signWebhookBody } from '../src/webhook-model.js';

test('blocks private and loopback addresses', () => {
  assert.equal(isBlockedIpAddress('10.0.0.5'), true);
  assert.equal(isBlockedIpAddress('192.168.1.1'), true);
  assert.equal(isBlockedIpAddress('127.0.0.1'), true);
  assert.equal(isBlockedIpAddress('169.254.169.254'), true);
  assert.equal(isBlockedIpAddress('172.16.0.1'), true);
  assert.equal(isBlockedIpAddress('::1'), true);
  assert.equal(isBlockedIpAddress('fc00::1'), true);
  assert.equal(isBlockedIpAddress('fe80::1'), true);
  assert.equal(isBlockedIpAddress('::ffff:10.0.0.1'), true);
  assert.equal(isBlockedIpAddress('1.1.1.1'), false);
  assert.equal(isBlockedIpAddress('8.8.8.8'), false);
});

test('assertSafeWebhookUrl requires https and blocks private DNS results', async () => {
  await assert.rejects(
    () => assertSafeWebhookUrl('http://example.com/hook'),
    /https/i
  );
  await assert.rejects(
    () =>
      assertSafeWebhookUrl('https://hooks.example.com/hook', {
        dnsLookup: async () => [{ address: '10.1.2.3', family: 4 }]
      }),
    /blocked/i
  );
  const ok = await assertSafeWebhookUrl('https://hooks.example.com/hook', {
    dnsLookup: async () => [{ address: '1.1.1.1', family: 4 }]
  });
  assert.equal(ok.hostname, 'hooks.example.com');

  await assert.rejects(
    () => assertSafeWebhookUrl('http://127.0.0.1:9999/hook', { allowHttpLocal: false }),
    /https/i
  );
  const local = await assertSafeWebhookUrl('http://127.0.0.1:9999/hook', {
    allowHttpLocal: true
  });
  assert.equal(local.hostname, '127.0.0.1');
});

test('resolveSafeWebhookTarget returns pinned public address and rejects mixed private results', async () => {
  const target = await resolveSafeWebhookTarget('https://hooks.example.com/mail?x=1', {
    dnsLookup: async () => [
      { address: '1.1.1.1', family: 4 },
      { address: '8.8.8.8', family: 4 }
    ]
  });
  assert.equal(target.url.hostname, 'hooks.example.com');
  assert.deepEqual(target.addresses, ['1.1.1.1', '8.8.8.8']);
  assert.equal(target.pinnedAddress, '1.1.1.1');
  assert.equal(
    buildPinnedWebhookUrl(target.url, target.pinnedAddress).href,
    'https://1.1.1.1/mail?x=1'
  );

  await assert.rejects(
    () =>
      resolveSafeWebhookTarget('https://hooks.example.com/hook', {
        dnsLookup: async () => [
          { address: '1.1.1.1', family: 4 },
          { address: '10.0.0.1', family: 4 }
        ]
      }),
    /blocked/i
  );
});

test('posts signed body to pinned IP with Host/SNI and marks success on 2xx', async () => {
  initDatabase(tempDataDir(), 'test-secret');
  const alice = createUser({ username: 'alice', email: 'alice@example.com', password: 'password123' });
  const webhook = createWebhook(alice.id, {
    name: 'Primary',
    url: 'https://hooks.example.com/mail',
    events: ['sent']
  });
  enqueueWebhookDeliveries({
    id: 11,
    userId: alice.id,
    domainId: null,
    status: 'sent',
    sender: 'noreply@example.com',
    recipients: ['user@example.com'],
    subject: 'Hello',
    detail: 'ok',
    queueId: 'Q11',
    deliveredAt: '2026-07-09T12:00:01.000Z'
  });

  const [before] = listWebhookDeliveries(alice.id);
  const fetchCalls = [];
  const fixedSeconds = 1_700_000_000;

  const result = await processWebhookBatch({
    batchSize: 5,
    nowSeconds: () => fixedSeconds,
    dnsLookup: async () => [{ address: '1.1.1.1', family: 4 }],
    fetchImpl: async (url, options) => {
      fetchCalls.push({ url, options });
      return {
        status: 204,
        text: async () => ''
      };
    }
  });

  assert.equal(result.claimed, 1);
  assert.equal(fetchCalls.length, 1);
  // Connect by pinned IP (no second DNS); Host/SNI keep original hostname.
  assert.equal(fetchCalls[0].url, 'https://1.1.1.1/mail');
  assert.equal(fetchCalls[0].options.method, 'POST');
  assert.equal(fetchCalls[0].options.redirect, 'manual');
  assert.equal(fetchCalls[0].options.headers['Content-Type'], 'application/json');
  assert.equal(fetchCalls[0].options.headers['User-Agent'], 'MailHub-Webhook/1.0');
  assert.equal(fetchCalls[0].options.headers.Host, 'hooks.example.com');
  assert.equal(fetchCalls[0].options.servername, 'hooks.example.com');
  assert.equal(fetchCalls[0].options.pinnedAddress, '1.1.1.1');
  assert.equal(fetchCalls[0].options.headers['X-MailHub-Event'], 'email.sent');
  assert.equal(fetchCalls[0].options.headers['X-MailHub-Delivery'], `whd_${before.id}`);
  assert.equal(
    fetchCalls[0].options.headers['X-MailHub-Signature'],
    signWebhookBody(before.payloadJson, webhook.secret, fixedSeconds)
  );
  assert.equal(fetchCalls[0].options.body, before.payloadJson);

  const [after] = listWebhookDeliveries(alice.id);
  assert.equal(after.status, 'success');
  assert.equal(after.attemptCount, 1);
  assert.equal(after.responseStatus, 204);
  assert.equal(after.error, '');
});

test('schedules retry on 500', async () => {
  initDatabase(tempDataDir(), 'test-secret');
  const alice = createUser({ username: 'alice', email: 'alice@example.com', password: 'password123' });
  createWebhook(alice.id, {
    name: 'Retry',
    url: 'https://hooks.example.com/retry',
    events: ['failed']
  });
  enqueueWebhookDeliveries({
    id: 12,
    userId: alice.id,
    domainId: null,
    status: 'failed',
    sender: 'noreply@example.com',
    recipients: ['user@example.com'],
    subject: 'Nope',
    detail: 'bounce',
    queueId: 'Q12'
  });

  await processWebhookBatch({
    dnsLookup: async () => [{ address: '1.1.1.1', family: 4 }],
    fetchImpl: async () => ({
      status: 500,
      text: async () => 'upstream error body'
    })
  });

  const [delivery] = listWebhookDeliveries(alice.id);
  assert.equal(delivery.status, 'pending');
  assert.equal(delivery.attemptCount, 1);
  assert.equal(delivery.responseStatus, 500);
  assert.match(delivery.error, /HTTP 500/);
  assert.match(delivery.responseBodyPreview, /upstream error/);
  assert.ok(Date.parse(delivery.nextAttemptAt) > Date.now());
});

test('marks dead after max attempts', async () => {
  initDatabase(tempDataDir(), 'test-secret');
  const alice = createUser({ username: 'alice', email: 'alice@example.com', password: 'password123' });
  const webhook = createWebhook(alice.id, {
    name: 'Dead',
    url: 'https://hooks.example.com/dead',
    events: ['bounced']
  });
  enqueueWebhookDeliveries({
    id: 13,
    userId: alice.id,
    domainId: null,
    status: 'bounced',
    sender: 'noreply@example.com',
    recipients: ['user@example.com'],
    subject: 'Bounced',
    detail: '',
    queueId: 'Q13'
  });

  // Inject claim so retries are not blocked by future next_attempt_at backoff.
  for (let attempt = 0; attempt < MAX_WEBHOOK_ATTEMPTS; attempt += 1) {
    const delivery = listWebhookDeliveries(alice.id)[0];
    await processWebhookBatch({
      claim: () => [
        {
          delivery: { ...delivery, status: 'processing' },
          webhook: {
            id: webhook.id,
            url: webhook.url,
            secret: webhook.secret
          }
        }
      ],
      reap: () => 0,
      dnsLookup: async () => [{ address: '1.1.1.1', family: 4 }],
      fetchImpl: async () => ({
        status: 503,
        text: async () => 'down'
      })
    });
  }

  const dead = listWebhookDeliveries(alice.id)[0];
  assert.equal(dead.status, 'dead');
  assert.equal(dead.attemptCount, MAX_WEBHOOK_ATTEMPTS);
});

test('rejects private IP targets as permanent dead without calling fetch', async () => {
  initDatabase(tempDataDir(), 'test-secret');
  const alice = createUser({ username: 'alice', email: 'alice@example.com', password: 'password123' });
  createWebhook(alice.id, {
    name: 'Internal',
    url: 'https://metadata.internal/hook',
    events: ['sent']
  });
  enqueueWebhookDeliveries({
    id: 14,
    userId: alice.id,
    domainId: null,
    status: 'sent',
    sender: 'noreply@example.com',
    recipients: ['user@example.com'],
    subject: 'SSRF',
    detail: '',
    queueId: 'Q14'
  });

  let fetchCalled = false;
  await processWebhookBatch({
    dnsLookup: async () => [{ address: '169.254.169.254', family: 4 }],
    fetchImpl: async () => {
      fetchCalled = true;
      return { status: 200, text: async () => 'ok' };
    }
  });

  assert.equal(fetchCalled, false);
  const [delivery] = listWebhookDeliveries(alice.id);
  assert.equal(delivery.status, 'dead');
  assert.equal(delivery.attemptCount, 1);
  assert.match(delivery.error, /blocked/i);
  assert.equal(claimWebhookDeliveries(5).length, 0);
});

test('missing webhook secret marks delivery permanently dead', async () => {
  initDatabase(tempDataDir(), 'test-secret');
  const alice = createUser({ username: 'alice', email: 'alice@example.com', password: 'password123' });
  const webhook = createWebhook(alice.id, {
    name: 'NoSecret',
    url: 'https://hooks.example.com/no-secret',
    events: ['sent']
  });
  enqueueWebhookDeliveries({
    id: 15,
    userId: alice.id,
    domainId: null,
    status: 'sent',
    sender: 'noreply@example.com',
    recipients: ['user@example.com'],
    subject: 'Secret',
    detail: '',
    queueId: 'Q15'
  });

  const delivery = listWebhookDeliveries(alice.id)[0];
  await processWebhookBatch({
    claim: () => [
      {
        delivery: { ...delivery, status: 'processing' },
        webhook: {
          id: webhook.id,
          url: webhook.url,
          secret: ''
        }
      }
    ],
    reap: () => 0,
    fetchImpl: async () => {
      throw new Error('should not fetch');
    }
  });

  const [after] = listWebhookDeliveries(alice.id);
  assert.equal(after.status, 'dead');
  assert.equal(after.attemptCount, 1);
  assert.match(after.error, /missing url or secret/i);
});

test('bounds response body preview without consuming unbounded text()', async () => {
  initDatabase(tempDataDir(), 'test-secret');
  const alice = createUser({ username: 'alice', email: 'alice@example.com', password: 'password123' });
  createWebhook(alice.id, {
    name: 'Body',
    url: 'https://hooks.example.com/body',
    events: ['sent']
  });
  enqueueWebhookDeliveries({
    id: 16,
    userId: alice.id,
    domainId: null,
    status: 'sent',
    sender: 'noreply@example.com',
    recipients: ['user@example.com'],
    subject: 'Body',
    detail: '',
    queueId: 'Q16'
  });

  const huge = 'x'.repeat(20_000);
  let textCalls = 0;
  await processWebhookBatch({
    dnsLookup: async () => [{ address: '1.1.1.1', family: 4 }],
    fetchImpl: async () => ({
      status: 200,
      body: Readable.from([Buffer.from(huge)]),
      text: async () => {
        textCalls += 1;
        return huge;
      }
    })
  });

  assert.equal(textCalls, 0);
  const [delivery] = listWebhookDeliveries(alice.id);
  assert.equal(delivery.status, 'success');
  assert.ok(delivery.responseBodyPreview.length <= 2048);
  assert.ok(delivery.responseBodyPreview.length > 0);
  assert.match(delivery.responseBodyPreview, /^x+$/);
});

test('startWebhookWorker can be skipped and stopped', async () => {
  assert.equal(startWebhookWorker({ enabled: false }), null);
  const handle = startWebhookWorker({
    enabled: true,
    intervalMs: 60_000,
    fetchImpl: async () => ({ status: 200, text: async () => '' })
  });
  assert.ok(handle);
  assert.equal(typeof handle.stop, 'function');
  stopWebhookWorker();
  stopWebhookWorker();
});

function tempDataDir() {
  return mkdtempSync(path.join(tmpdir(), 'mailhub-webhook-dispatcher-'));
}
