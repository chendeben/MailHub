import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

import {
  claimWebhookDeliveries,
  completeWebhookDeliveryFailure,
  completeWebhookDeliverySuccess,
  createDomain,
  createUser,
  createWebhook,
  deleteWebhook,
  enqueueWebhookDeliveries,
  enqueueWebhookTestDelivery,
  getWebhook,
  initDatabase,
  listWebhookDeliveries,
  listWebhooks,
  logSendEvent,
  replayWebhookDelivery,
  rotateWebhookSecret,
  updateSendEventDelivery,
  updateWebhook
} from '../src/db.js';
import { MAX_WEBHOOK_ATTEMPTS } from '../src/webhook-model.js';

test('isolates webhooks by user and supports domain scope filter', () => {
  initDatabase(tempDataDir(), 'test-secret');
  const alice = createUser({ username: 'alice', email: 'alice@example.com', password: 'password123' });
  const bob = createUser({ username: 'bob', email: 'bob@example.com', password: 'password123' });
  const aliceDomain = createDomain(alice.id, domainFixture('alice.example'));

  createWebhook(alice.id, {
    name: 'Alice account',
    url: 'https://hooks.alice.example/account',
    events: ['sent']
  });
  createWebhook(alice.id, {
    name: 'Alice domain',
    url: 'https://hooks.alice.example/domain',
    events: ['failed'],
    domainId: aliceDomain.id
  });
  createWebhook(bob.id, {
    name: 'Bob account',
    url: 'https://hooks.bob.example/account',
    events: ['sent', 'bounced']
  });

  assert.equal(listWebhooks(alice.id).length, 2);
  assert.equal(listWebhooks(bob.id).length, 1);
  assert.equal(listWebhooks(alice.id, { domainId: null }).length, 1);
  assert.equal(listWebhooks(alice.id, { domainId: aliceDomain.id }).length, 1);
  assert.equal(listWebhooks(alice.id, { domainId: aliceDomain.id })[0].name, 'Alice domain');
  assert.equal(listWebhooks(bob.id, { domainId: aliceDomain.id }).length, 0);
});

test('create returns secret once; list and get omit secret', () => {
  initDatabase(tempDataDir(), 'test-secret');
  const alice = createUser({ username: 'alice', email: 'alice@example.com', password: 'password123' });

  const created = createWebhook(alice.id, {
    name: 'Primary',
    url: 'https://hooks.example.com/mail',
    events: ['sent', 'failed']
  });
  assert.ok(created.secret);
  assert.match(created.secret, /^whsec_/);
  assert.equal(created.secretPrefix, created.secret.slice(0, 8));
  assert.deepEqual(created.events, ['sent', 'failed']);
  assert.equal(created.enabled, true);
  assert.equal('secret' in listWebhooks(alice.id)[0], false);
  assert.equal('secret' in getWebhook(created.id, alice.id), false);
  assert.equal(listWebhooks(alice.id)[0].secretPrefix, created.secretPrefix);

  const rotated = rotateWebhookSecret(alice.id, created.id);
  assert.ok(rotated.secret);
  assert.notEqual(rotated.secret, created.secret);
  assert.equal(rotated.secretPrefix, rotated.secret.slice(0, 8));
  assert.equal('secret' in getWebhook(created.id, alice.id), false);

  const updated = updateWebhook(alice.id, created.id, {
    name: 'Renamed',
    enabled: false,
    events: ['bounced']
  });
  assert.equal(updated.name, 'Renamed');
  assert.equal(updated.enabled, false);
  assert.deepEqual(updated.events, ['bounced']);
  assert.equal(deleteWebhook(alice.id, created.id), true);
  assert.equal(getWebhook(created.id, alice.id), null);
});

test('enqueueWebhookDeliveries is idempotent per webhook+event+send_event', () => {
  initDatabase(tempDataDir(), 'test-secret');
  const alice = createUser({ username: 'alice', email: 'alice@example.com', password: 'password123' });
  const domain = createDomain(alice.id, domainFixture('alice.example'));
  const webhook = createWebhook(alice.id, {
    name: 'Account',
    url: 'https://hooks.example.com/a',
    events: ['sent', 'failed']
  });

  const sendEvent = {
    id: 42,
    userId: alice.id,
    domainId: domain.id,
    status: 'sent',
    sender: 'noreply@alice.example',
    recipients: ['user@example.com'],
    subject: 'Hello',
    detail: 'ok',
    queueId: 'QUEUE42',
    deliveredAt: '2026-07-09T12:00:01.000Z'
  };

  const first = enqueueWebhookDeliveries(sendEvent);
  const second = enqueueWebhookDeliveries(sendEvent);
  assert.equal(first.length, 1);
  assert.equal(second.length, 0);

  const deliveries = listWebhookDeliveries(alice.id);
  assert.equal(deliveries.length, 1);
  assert.equal(deliveries[0].webhookId, webhook.id);
  assert.equal(deliveries[0].sendEventId, 42);
  assert.equal(deliveries[0].eventType, 'sent');
  assert.equal(deliveries[0].status, 'pending');
  assert.equal(deliveries[0].attemptCount, 0);

  const payload = JSON.parse(deliveries[0].payloadJson);
  assert.equal(payload.id, `whd_${deliveries[0].id}`);
  assert.equal(payload.type, 'email.sent');
  assert.equal(payload.data.message_id, 'mh-42');
  assert.equal(payload.data.domain, 'alice.example');
  assert.equal(payload.data.queue_id, 'QUEUE42');
});

test('domain override skips account webhooks for that event', () => {
  initDatabase(tempDataDir(), 'test-secret');
  const alice = createUser({ username: 'alice', email: 'alice@example.com', password: 'password123' });
  const domain = createDomain(alice.id, domainFixture('override.example'));
  const account = createWebhook(alice.id, {
    name: 'Account',
    url: 'https://hooks.example.com/account',
    events: ['sent', 'failed']
  });
  const domainHook = createWebhook(alice.id, {
    name: 'Domain',
    url: 'https://hooks.example.com/domain',
    events: ['sent'],
    domainId: domain.id
  });

  enqueueWebhookDeliveries({
    id: 7,
    userId: alice.id,
    domainId: domain.id,
    domain: 'override.example',
    status: 'sent',
    sender: 'noreply@override.example',
    recipients: ['a@example.com'],
    subject: 'Override',
    detail: '',
    queueId: 'Q7'
  });

  const sent = listWebhookDeliveries(alice.id);
  assert.equal(sent.length, 1);
  assert.equal(sent[0].webhookId, domainHook.id);

  enqueueWebhookDeliveries({
    id: 8,
    userId: alice.id,
    domainId: domain.id,
    domain: 'override.example',
    status: 'failed',
    sender: 'noreply@override.example',
    recipients: ['a@example.com'],
    subject: 'Fallback',
    detail: 'error',
    queueId: 'Q8'
  });

  const failed = listWebhookDeliveries(alice.id, { eventType: 'failed' });
  assert.equal(failed.length, 1);
  assert.equal(failed[0].webhookId, account.id);
});

test('logSendEvent with failed status creates webhook delivery', () => {
  initDatabase(tempDataDir(), 'test-secret');
  const alice = createUser({ username: 'alice', email: 'alice@example.com', password: 'password123' });
  const domain = createDomain(alice.id, domainFixture('fail.example'));
  createWebhook(alice.id, {
    name: 'Failures',
    url: 'https://hooks.example.com/failed',
    events: ['failed']
  });

  const eventId = logSendEvent({
    userId: alice.id,
    domainId: domain.id,
    sender: 'noreply@fail.example',
    recipients: ['user@example.com'],
    subject: 'Boom',
    status: 'failed',
    detail: 'SMTP rejected'
  });

  const deliveries = listWebhookDeliveries(alice.id);
  assert.equal(deliveries.length, 1);
  assert.equal(deliveries[0].sendEventId, eventId);
  assert.equal(deliveries[0].eventType, 'failed');
  const payload = JSON.parse(deliveries[0].payloadJson);
  assert.equal(payload.type, 'email.failed');
  assert.equal(payload.data.domain, 'fail.example');
  assert.equal(payload.data.detail, 'SMTP rejected');
});

test('updateSendEventDelivery terminal status change enqueues delivery', () => {
  initDatabase(tempDataDir(), 'test-secret');
  const alice = createUser({ username: 'alice', email: 'alice@example.com', password: 'password123' });
  const domain = createDomain(alice.id, domainFixture('track.example'));
  createWebhook(alice.id, {
    name: 'Sent',
    url: 'https://hooks.example.com/sent',
    events: ['sent']
  });

  const eventId = logSendEvent({
    userId: alice.id,
    domainId: domain.id,
    sender: 'noreply@track.example',
    recipients: ['recipient@example.net'],
    subject: 'Tracked',
    status: 'queued',
    detail: '250 2.0.0 Ok: queued as 1DAEBC3EC8'
  });
  assert.equal(listWebhookDeliveries(alice.id).length, 0);

  assert.equal(
    updateSendEventDelivery('1DAEBC3EC8', {
      at: '2026-07-08T04:15:21.000Z',
      queueId: '1DAEBC3EC8',
      recipient: 'recipient@example.net',
      relay: 'mx.example.net[203.0.113.25]:25',
      dsn: '2.0.0',
      status: 'sent',
      response: '250 OK',
      raw: 'raw postfix line'
    }),
    true
  );

  const deliveries = listWebhookDeliveries(alice.id);
  assert.equal(deliveries.length, 1);
  assert.equal(deliveries[0].sendEventId, eventId);
  assert.equal(deliveries[0].eventType, 'sent');
  const payload = JSON.parse(deliveries[0].payloadJson);
  assert.equal(payload.type, 'email.sent');
  assert.equal(payload.data.domain, 'track.example');
  assert.equal(payload.data.queue_id, '1DAEBC3EC8');
  assert.equal(payload.data.delivered_at, '2026-07-08T04:15:21.000Z');

  // Same terminal status again (duplicate attempt ignored) must not create another delivery.
  updateSendEventDelivery('1DAEBC3EC8', {
    at: '2026-07-08T04:15:21.000Z',
    queueId: '1DAEBC3EC8',
    recipient: 'recipient@example.net',
    relay: 'mx.example.net[203.0.113.25]:25',
    dsn: '2.0.0',
    status: 'sent',
    response: '250 OK',
    raw: 'raw postfix line'
  });
  assert.equal(listWebhookDeliveries(alice.id).length, 1);
});

test('claim, complete success/failure, replay, test delivery, and dead path', () => {
  initDatabase(tempDataDir(), 'test-secret');
  const alice = createUser({ username: 'alice', email: 'alice@example.com', password: 'password123' });
  createDomain(alice.id, domainFixture('worker.example'));
  const webhook = createWebhook(alice.id, {
    name: 'Worker',
    url: 'https://hooks.example.com/worker',
    events: ['sent', 'failed']
  });

  enqueueWebhookDeliveries({
    id: 99,
    userId: alice.id,
    domainId: null,
    status: 'sent',
    sender: 'noreply@worker.example',
    recipients: ['a@example.com'],
    subject: 'Work',
    detail: '',
    queueId: 'W99'
  });

  const claimed = claimWebhookDeliveries(5);
  assert.equal(claimed.length, 1);
  assert.equal(claimed[0].webhook.id, webhook.id);
  assert.equal(claimed[0].webhook.url, 'https://hooks.example.com/worker');
  assert.ok(claimed[0].webhook.secret);
  assert.equal(claimed[0].delivery.status, 'processing');
  assert.match(claimed[0].webhook.secret, /^whsec_/);

  const success = completeWebhookDeliverySuccess(claimed[0].delivery.id, {
    responseStatus: 200,
    bodyPreview: 'ok'
  });
  assert.equal(success.status, 'success');
  assert.equal(success.attemptCount, 1);
  assert.equal(success.responseStatus, 200);

  const testDelivery = enqueueWebhookTestDelivery(alice.id, webhook.id);
  assert.equal(testDelivery.sendEventId, 0);
  assert.equal(testDelivery.status, 'pending');
  const testPayload = JSON.parse(testDelivery.payloadJson);
  assert.equal(testPayload.data.test, true);
  assert.equal(testPayload.data.message_id, 'mh-test');
  assert.equal(testPayload.id, `whd_${testDelivery.id}`);

  const reused = enqueueWebhookTestDelivery(alice.id, webhook.id);
  assert.equal(reused.id, testDelivery.id);
  assert.equal(reused.status, 'pending');
  assert.equal(reused.attemptCount, 0);

  const claimedTest = claimWebhookDeliveries(5);
  assert.equal(claimedTest.length, 1);
  const failed = completeWebhookDeliveryFailure(claimedTest[0].delivery.id, {
    responseStatus: 500,
    bodyPreview: 'err',
    error: 'server error'
  });
  assert.equal(failed.status, 'pending');
  assert.equal(failed.attemptCount, 1);
  assert.ok(failed.nextAttemptAt > failed.lastAttemptAt);

  const replayed = replayWebhookDelivery(alice.id, failed.id);
  assert.equal(replayed.status, 'pending');
  assert.equal(replayed.attemptCount, 0);
  assert.equal(replayed.error, '');
  assert.equal(replayed.responseBodyPreview, '');

  const processing = claimWebhookDeliveries(1)[0];
  assert.throws(() => replayWebhookDelivery(alice.id, processing.delivery.id), /投递中|租约/);

  enqueueWebhookDeliveries({
    id: 100,
    userId: alice.id,
    status: 'failed',
    sender: 'noreply@worker.example',
    recipients: ['b@example.com'],
    subject: 'Dead path',
    detail: 'x'
  });
  let row = listWebhookDeliveries(alice.id, { eventType: 'failed' }).find((d) => d.sendEventId === 100);
  assert.ok(row);
  while (row.status !== 'dead') {
    row = completeWebhookDeliveryFailure(row.id, { responseStatus: 502, error: 'down' });
  }
  assert.equal(row.status, 'dead');
  assert.equal(row.attemptCount, MAX_WEBHOOK_ATTEMPTS);

  const reset = replayWebhookDelivery(alice.id, row.id);
  assert.equal(reset.status, 'pending');
  assert.equal(reset.attemptCount, 0);
});

function domainFixture(domain) {
  return {
    domain,
    selector: 'mh202607',
    verificationToken: 'token',
    dkimPublic: 'public',
    dkimPrivate: 'private',
    senderHost: `mail.${domain}`,
    sendingIp: '127.0.0.1',
    spfExtra: '',
    dmarcPolicy: 'none',
    dmarcRua: ''
  };
}

function tempDataDir() {
  return mkdtempSync(path.join(tmpdir(), 'mailhub-webhook-db-'));
}
