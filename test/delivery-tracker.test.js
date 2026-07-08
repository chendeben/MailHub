import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

import {
  extractQueueIdFromSmtpResponse,
  parsePostfixLogLine
} from '../src/delivery-tracker.js';
import {
  createDomain,
  createUser,
  initDatabase,
  listSendEvents,
  logSendEvent,
  updateSendEventDelivery
} from '../src/db.js';

test('extracts postfix queue ids from SMTP queue responses', () => {
  assert.equal(extractQueueIdFromSmtpResponse('250 2.0.0 Ok: queued as 1DAEBC3EC8'), '1DAEBC3EC8');
  assert.equal(extractQueueIdFromSmtpResponse('250 OK queued as ABC123'), 'ABC123');
  assert.equal(extractQueueIdFromSmtpResponse('250 message accepted'), '');
});

test('parses postfix delivery status lines', () => {
  const event = parsePostfixLogLine(
    'Jul 08 04:15:21 in postfix/smtp[300]: 1DAEBC3EC8: to=<recipient@example.net>, relay=mx.example.net[203.0.113.25]:25, delay=3.4, delays=0.04/0.11/1.7/1.6, dsn=2.0.0, status=sent (250 OK: queued as.)'
  );

  assert.equal(event.queueId, '1DAEBC3EC8');
  assert.equal(event.recipient, 'recipient@example.net');
  assert.equal(event.relay, 'mx.example.net[203.0.113.25]:25');
  assert.equal(event.dsn, '2.0.0');
  assert.equal(event.status, 'sent');
  assert.equal(event.response, '250 OK: queued as.');
});

test('updates send events from postfix delivery attempts', () => {
  initDatabase(tempDataDir(), 'test-secret');
  const user = createUser({ username: 'alice', email: 'alice@example.com', password: 'password123' });
  const domain = createDomain(user.id, domainFixture('sender.example.com'));
  logSendEvent({
    userId: user.id,
    domainId: domain.id,
    sender: 'noreply@sender.example.com',
    recipients: ['recipient@example.net'],
    subject: 'Tracked',
    status: 'queued',
    detail: '250 2.0.0 Ok: queued as 1DAEBC3EC8'
  });

  const updated = updateSendEventDelivery('1DAEBC3EC8', {
    at: '2026-07-08T04:15:21.000Z',
    queueId: '1DAEBC3EC8',
    recipient: 'recipient@example.net',
    relay: 'mx.example.net[203.0.113.25]:25',
    dsn: '2.0.0',
    status: 'sent',
    response: '250 OK: queued as.',
    raw: 'raw postfix line'
  });

  assert.equal(updated, true);
  const [event] = listSendEvents(user.id);
  assert.equal(event.queueId, '1DAEBC3EC8');
  assert.equal(event.status, 'sent');
  assert.equal(event.deliveredAt, '2026-07-08T04:15:21.000Z');
  assert.equal(event.deliveryAttempts.length, 1);
  assert.equal(event.deliveryAttempts[0].status, 'sent');
  assert.equal(event.deliveryAttempts[0].recipient, 'recipient@example.net');

  updateSendEventDelivery('1DAEBC3EC8', {
    at: '2026-07-08T04:15:21.000Z',
    queueId: '1DAEBC3EC8',
    recipient: 'recipient@example.net',
    relay: 'mx.example.net[203.0.113.25]:25',
    dsn: '2.0.0',
    status: 'sent',
    response: '250 OK: queued as.',
    raw: 'raw postfix line'
  });

  assert.equal(listSendEvents(user.id)[0].deliveryAttempts.length, 1);
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
  return mkdtempSync(path.join(tmpdir(), 'mailhub-test-'));
}
