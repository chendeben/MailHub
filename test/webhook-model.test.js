import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { test } from 'node:test';

import {
  WEBHOOK_EVENTS,
  TERMINAL_WEBHOOK_EVENTS,
  MAX_WEBHOOK_ATTEMPTS,
  WEBHOOK_LEASE_MS,
  eventTypeForStatus,
  resolveWebhooksForEvent,
  buildWebhookPayload,
  signWebhookBody,
  nextBackoffMs,
  isTerminalWebhookStatus,
  normalizeWebhookEvents,
  parseWebhookEventsJson
} from '../src/webhook-model.js';

test('maps terminal statuses to email.* types', () => {
  assert.equal(eventTypeForStatus('sent'), 'email.sent');
  assert.equal(eventTypeForStatus('bounced'), 'email.bounced');
  assert.equal(eventTypeForStatus('failed'), 'email.failed');
  assert.equal(eventTypeForStatus('opened'), 'email.opened');
  assert.equal(eventTypeForStatus('clicked'), 'email.clicked');
  assert.equal(eventTypeForStatus('received'), 'email.received');
  assert.equal(eventTypeForStatus('queued'), null);
  assert.equal(eventTypeForStatus('deferred'), null);
});

test('supports engagement and receipt subscriptions without making them delivery terminal statuses', () => {
  assert.deepEqual(WEBHOOK_EVENTS, ['sent', 'bounced', 'failed', 'opened', 'clicked', 'received']);
  assert.equal(isTerminalWebhookStatus('opened'), false);
  assert.equal(isTerminalWebhookStatus('clicked'), false);
  assert.equal(isTerminalWebhookStatus('received'), false);
  assert.deepEqual(normalizeWebhookEvents(['clicked', 'opened', 'sent']), ['sent', 'opened', 'clicked']);
});

test('builds an inbound receipt payload without raw MIME content', () => {
  const payload = buildWebhookPayload({
    deliveryId: 9,
    eventType: 'email.received',
    createdAt: '2026-07-14T12:00:00.000Z',
    inboundMessage: {
      id: 55,
      mailboxId: 4,
      mailboxAddress: 'support@example.com',
      domain: 'example.com',
      sender: 'sender@example.net',
      recipients: ['support@example.com'],
      subject: 'Inbound test',
      messageId: '<rfc-123@example.net>',
      textBody: 'Plain body',
      htmlBody: '<p>HTML body</p>',
      rawMessage: 'secret raw MIME',
      receivedAt: '2026-07-14T11:59:58.000Z'
    }
  });

  assert.equal(payload.type, 'email.received');
  assert.equal(payload.data.inbound_message_id, 55);
  assert.equal(payload.data.mailbox, 'support@example.com');
  assert.equal(payload.data.message_id, '<rfc-123@example.net>');
  assert.equal(payload.data.rfc_message_id, '<rfc-123@example.net>');
  assert.equal(payload.data.text, 'Plain body');
  assert.equal(payload.data.html, '<p>HTML body</p>');
  assert.equal('raw_message' in payload.data, false);
  assert.equal(JSON.stringify(payload).includes('secret raw MIME'), false);
});

test('isTerminalWebhookStatus matches terminal set', () => {
  assert.equal(isTerminalWebhookStatus('sent'), true);
  assert.equal(isTerminalWebhookStatus('bounced'), true);
  assert.equal(isTerminalWebhookStatus('failed'), true);
  assert.equal(isTerminalWebhookStatus('queued'), false);
  assert.equal(isTerminalWebhookStatus('processing'), false);
  assert.deepEqual(TERMINAL_WEBHOOK_EVENTS, ['sent', 'bounced', 'failed']);
  assert.equal(MAX_WEBHOOK_ATTEMPTS, 8);
  assert.equal(WEBHOOK_LEASE_MS, 2 * 60 * 1000);
});

test('domain webhooks override account for the same event', () => {
  const account = [
    { id: 1, domainId: null, enabled: true, events: ['sent', 'failed'] },
    { id: 2, domainId: null, enabled: true, events: ['bounced'] }
  ];
  const domain = [
    { id: 3, domainId: 9, enabled: true, events: ['sent'] }
  ];
  const resolved = resolveWebhooksForEvent({
    accountWebhooks: account,
    domainWebhooks: domain,
    eventType: 'sent'
  });
  assert.deepEqual(resolved.map((w) => w.id), [3]);
});

test('falls back to account when domain has no matching enabled subscription', () => {
  const resolved = resolveWebhooksForEvent({
    accountWebhooks: [{ id: 1, domainId: null, enabled: true, events: ['failed'] }],
    domainWebhooks: [{ id: 3, domainId: 9, enabled: true, events: ['sent'] }],
    eventType: 'failed'
  });
  assert.deepEqual(resolved.map((w) => w.id), [1]);
});

test('skips disabled webhooks and unsubscribed events', () => {
  const resolved = resolveWebhooksForEvent({
    accountWebhooks: [
      { id: 1, domainId: null, enabled: false, events: ['sent'] },
      { id: 2, domainId: null, enabled: 'false', events: ['sent'] },
      { id: 3, domainId: null, enabled: true, events: ['bounced'] },
      { id: 4, domainId: null, enabled: true, events: ['sent'] }
    ],
    domainWebhooks: [],
    eventType: 'sent'
  });
  assert.deepEqual(resolved.map((w) => w.id), [4]);
});

test('builds webhook payload for real and test deliveries', () => {
  const real = buildWebhookPayload({
    deliveryId: 42,
    eventType: 'email.sent',
    createdAt: '2026-07-09T12:00:00.000Z',
    sendEvent: {
      id: 7,
      status: 'sent',
      queueId: 'A1B2C3',
      domain: 'example.com',
      sender: 'noreply@example.com',
      recipients: ['user@example.com'],
      subject: 'Hello',
      detail: 'ok',
      deliveredAt: '2026-07-09T12:00:01.000Z'
    }
  });
  assert.equal(real.id, 'whd_42');
  assert.equal(real.type, 'email.sent');
  assert.equal(real.created_at, '2026-07-09T12:00:00.000Z');
  assert.equal(real.data.message_id, 'mh-7');
  assert.equal(real.data.send_event_id, 7);
  assert.equal(real.data.queue_id, 'A1B2C3');
  assert.equal(real.data.test, undefined);

  const synthetic = buildWebhookPayload({
    deliveryId: 1,
    eventType: 'email.failed',
    createdAt: '2026-07-09T12:00:00.000Z',
    sendEvent: {
      id: 0,
      status: 'failed',
      domain: 'example.com',
      sender: 'noreply@example.com',
      recipients: ['user@example.com'],
      subject: 'Test'
    },
    test: true
  });
  assert.equal(synthetic.data.test, true);
  assert.equal(synthetic.data.message_id, 'mh-test');
  assert.equal(synthetic.data.send_event_id, 0);
  assert.equal(synthetic.type, 'email.failed');
});

test('builds private engagement webhook payloads without full click destinations', () => {
  const payload = buildWebhookPayload({
    deliveryId: 51,
    eventType: 'email.clicked',
    createdAt: '2026-07-09T12:00:00.000Z',
    sendEvent: {
      id: 8,
      status: 'sent',
      domain: 'example.com',
      sender: 'noreply@example.com',
      recipients: ['reader@example.net'],
      subject: 'Tracked'
    },
    engagement: {
      type: 'click',
      occurredAt: '2026-07-09T12:00:00.000Z',
      source: 'direct',
      linkId: 4,
      targetOrigin: 'https://example.net'
    }
  });

  assert.equal(payload.type, 'email.clicked');
  assert.deepEqual(payload.data.engagement, {
    type: 'click',
    occurred_at: '2026-07-09T12:00:00.000Z',
    source: 'direct',
    link_id: 4,
    target_origin: 'https://example.net'
  });
  assert.equal(JSON.stringify(payload).includes('token='), false);
});

test('signs body with Stripe-style t and v1', () => {
  const body = '{"id":"whd_1"}';
  const secret = 'secret';
  const t = 1_700_000_000;
  const header = signWebhookBody(body, secret, t);
  assert.equal(header.startsWith('t=1700000000,v1='), true);
  assert.match(header, /^t=\d+,v1=[0-9a-f]{64}$/);

  const expected = crypto.createHmac('sha256', secret).update(`${t}.${body}`).digest('hex');
  assert.equal(header, `t=${t},v1=${expected}`);
});

test('backoff grows then caps', () => {
  assert.equal(nextBackoffMs(1), 60_000);
  assert.equal(nextBackoffMs(2), 300_000);
  assert.equal(nextBackoffMs(3), 1_800_000);
  assert.equal(nextBackoffMs(4), 7_200_000);
  assert.equal(nextBackoffMs(5), 21_600_000);
  assert.equal(nextBackoffMs(6), 43_200_000);
  assert.ok(nextBackoffMs(1) < nextBackoffMs(2));
  assert.equal(nextBackoffMs(6), nextBackoffMs(7));
  assert.equal(nextBackoffMs(10), nextBackoffMs(20));
});

test('normalizeWebhookEvents accepts non-empty subset of terminal events', () => {
  assert.deepEqual(normalizeWebhookEvents(['failed', 'sent', 'sent']), ['sent', 'failed']);
  assert.deepEqual(normalizeWebhookEvents(['bounced']), ['bounced']);
  assert.throws(() => normalizeWebhookEvents([]), /events/i);
  assert.throws(() => normalizeWebhookEvents(['queued']), /events/i);
  assert.throws(() => normalizeWebhookEvents(null), /events/i);
});

test('parseWebhookEventsJson parses JSON array of events', () => {
  assert.deepEqual(parseWebhookEventsJson('["sent","bounced"]'), ['sent', 'bounced']);
  assert.throws(() => parseWebhookEventsJson('not-json'), /events/i);
  assert.throws(() => parseWebhookEventsJson('[]'), /events/i);
});
