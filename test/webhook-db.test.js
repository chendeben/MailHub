import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';

import {
  claimWebhookDeliveries,
  completeWebhookDeliveryFailure,
  completeWebhookDeliverySuccess,
  createDomain,
  createInboundMailbox,
  createInboundMessage,
  createUser,
  createWebhook,
  deleteWebhook,
  enqueueWebhookDeliveries,
  enqueueInboundWebhookDeliveries,
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

test('migrates legacy webhook deliveries without losing send-event records', () => {
  const dataDir = tempDataDir();
  const database = new DatabaseSync(path.join(dataDir, 'mailhub.sqlite'));
  database.exec(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE webhooks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      domain_id INTEGER,
      name TEXT NOT NULL,
      url TEXT NOT NULL,
      secret_ciphertext TEXT NOT NULL,
      secret_prefix TEXT NOT NULL,
      events_json TEXT NOT NULL,
      enabled TEXT NOT NULL DEFAULT 'true',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE webhook_deliveries (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      webhook_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      send_event_id INTEGER NOT NULL,
      event_type TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      status TEXT NOT NULL,
      attempt_count INTEGER NOT NULL DEFAULT 0,
      next_attempt_at TEXT NOT NULL,
      last_attempt_at TEXT,
      response_status INTEGER,
      response_body_preview TEXT NOT NULL DEFAULT '',
      error TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL,
      FOREIGN KEY(webhook_id) REFERENCES webhooks(id) ON DELETE CASCADE,
      UNIQUE(webhook_id, send_event_id, event_type)
    );
    INSERT INTO users (id, username, email, password_hash, role, status, created_at, updated_at)
    VALUES (1, 'legacy', 'legacy@example.com', 'hash', 'user', 'active', '2026-07-14T00:00:00.000Z', '2026-07-14T00:00:00.000Z');
    INSERT INTO webhooks (id, user_id, name, url, secret_ciphertext, secret_prefix, events_json, enabled, created_at, updated_at)
    VALUES (1, 1, 'Legacy', 'https://hooks.example.com/legacy', 'secret', 'whsec_12', '["sent"]', 'true', '2026-07-14T00:00:00.000Z', '2026-07-14T00:00:00.000Z');
    INSERT INTO webhook_deliveries (id, webhook_id, user_id, send_event_id, event_type, payload_json, status, attempt_count, next_attempt_at, response_body_preview, error, created_at)
    VALUES (1, 1, 1, 42, 'sent', '{}', 'success', 1, '2026-07-14T00:00:00.000Z', '', '', '2026-07-14T00:00:00.000Z');
  `);
  database.close();

  initDatabase(dataDir, 'test-secret');
  const [delivery] = listWebhookDeliveries(1);
  assert.equal(delivery.sendEventId, 42);
  assert.equal(delivery.inboundMessageId, null);
  assert.equal(listWebhooks(1)[0].mailboxId, null);
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

test('mailbox webhooks only enqueue idempotent receipt callbacks for their stored mail', () => {
  initDatabase(tempDataDir(), 'test-secret');
  const alice = createUser({ username: 'inbound-alice', email: 'inbound-alice@example.com', password: 'password123' });
  const bob = createUser({ username: 'inbound-bob', email: 'inbound-bob@example.com', password: 'password123' });
  const domain = createDomain(alice.id, domainFixture('inbound-hook.example'));
  const mailbox = createInboundMailbox(alice.id, { address: 'support@inbound-hook.example' });
  const otherMailbox = createInboundMailbox(alice.id, { address: 'sales@inbound-hook.example' });
  const webhook = createWebhook(alice.id, {
    name: 'Support receipt',
    url: 'https://hooks.example.com/inbound',
    events: ['received'],
    mailboxId: mailbox.id
  });
  const sendWebhook = createWebhook(alice.id, {
    name: 'Sending only',
    url: 'https://hooks.example.com/send',
    events: ['sent']
  });

  assert.equal(webhook.domainId, null);
  assert.equal(webhook.mailboxId, mailbox.id);
  assert.equal(listWebhooks(alice.id, { mailboxId: mailbox.id }).length, 1);
  assert.equal(listWebhooks(alice.id, { domainId: null }).length, 1);
  assert.throws(() => createWebhook(alice.id, {
    name: 'Invalid account receipt',
    url: 'https://hooks.example.com/invalid-account',
    events: ['received']
  }), /received/);
  assert.throws(() => createWebhook(alice.id, {
    name: 'Invalid mailbox send',
    url: 'https://hooks.example.com/invalid-mailbox',
    events: ['sent'],
    mailboxId: mailbox.id
  }), /邮箱 Webhook/);
  assert.throws(() => createWebhook(bob.id, {
    name: 'Other user mailbox',
    url: 'https://hooks.example.com/other-user',
    events: ['received'],
    mailboxId: mailbox.id
  }), /收信邮箱/);

  const inboundMessage = createInboundMessage(mailbox, {
    sender: 'sender@example.net',
    recipients: ['support@inbound-hook.example'],
    subject: 'Receipt callback',
    messageId: '<inbound-message@example.net>',
    textBody: 'Plain text',
    htmlBody: '<p>HTML</p>'
  });
  const unrelatedMessage = createInboundMessage(otherMailbox, {
    sender: 'sender@example.net',
    recipients: ['sales@inbound-hook.example'],
    subject: 'Other mailbox'
  });

  assert.equal(enqueueInboundWebhookDeliveries(inboundMessage).length, 1);
  assert.equal(enqueueInboundWebhookDeliveries(inboundMessage).length, 0);
  assert.equal(enqueueInboundWebhookDeliveries(unrelatedMessage).length, 0);
  enqueueWebhookDeliveries({
    id: 99,
    userId: alice.id,
    domainId: domain.id,
    status: 'sent',
    sender: 'noreply@inbound-hook.example',
    recipients: ['reader@example.net'],
    subject: 'Sending path'
  });

  const deliveries = listWebhookDeliveries(alice.id);
  const received = deliveries.find((delivery) => delivery.eventType === 'received');
  assert.ok(received);
  assert.equal(received.webhookId, webhook.id);
  assert.equal(received.sendEventId, 0);
  assert.equal(received.inboundMessageId, inboundMessage.id);
  const payload = JSON.parse(received.payloadJson);
  assert.equal(payload.type, 'email.received');
  assert.equal(payload.data.mailbox, 'support@inbound-hook.example');
  assert.equal(payload.data.rfc_message_id, '<inbound-message@example.net>');
  assert.equal(payload.data.text, 'Plain text');
  assert.equal(payload.data.html, '<p>HTML</p>');
  assert.equal('raw_message' in payload.data, false);
  assert.equal(deliveries.find((delivery) => delivery.eventType === 'sent')?.webhookId, sendWebhook.id);

  const testDelivery = enqueueWebhookTestDelivery(alice.id, webhook.id);
  assert.equal(testDelivery.inboundMessageId, 0);
  assert.equal(JSON.parse(testDelivery.payloadJson).type, 'email.received');

  updateWebhook(alice.id, webhook.id, { enabled: false });
  const disabledMessage = createInboundMessage(mailbox, {
    sender: 'sender@example.net',
    recipients: ['support@inbound-hook.example'],
    subject: 'Disabled callback'
  });
  assert.equal(enqueueInboundWebhookDeliveries(disabledMessage).length, 0);
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
