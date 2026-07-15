import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

import {
  createDomain,
  createInboundMailbox,
  createInboundMessage,
  createUser,
  getInboundMailboxByAddress,
  getInboundMessage,
  initDatabase,
  listInboundMailboxes,
  listInboundMessages,
  markInboundMessageRead,
  resolveInboundRecipient,
  updateDomain,
  verifySmtpCredential
} from '../src/db.js';

test('users can create inbound mailboxes and read received messages', () => {
  initDatabase(mkdtempSync(path.join(tmpdir(), 'mailhub-inbound-db-')), 'inbound-secret');
  const user = createUser({ username: 'inbound-user', email: 'inbound-user@example.com', password: 'password123' });
  createDomain(user.id, {
    domain: 'inbound.example',
    selector: 'mh',
    verificationToken: 'verify',
    dkimPublic: 'public',
    dkimPrivate: 'private',
    senderHost: 'mail.inbound.example',
    sendingIp: '192.0.2.10',
    spfExtra: '',
    dmarcPolicy: 'none',
    dmarcRua: ''
  });

  const mailbox = createInboundMailbox(user.id, {
    address: 'Support@Inbound.Example',
    displayName: 'Support',
    password: 'mailbox-pass-123',
    aliases: 'help desk',
    forwardTo: 'archive@example.net, ops@example.net',
    keepForwarded: false,
    quotaMb: 512
  });
  assert.equal(mailbox.address, 'support@inbound.example');
  assert.equal(mailbox.displayName, 'Support');
  assert.equal(mailbox.passwordSet, true);
  assert.deepEqual(mailbox.aliases, ['help', 'desk']);
  assert.deepEqual(mailbox.forwardTo, ['archive@example.net', 'ops@example.net']);
  assert.equal(mailbox.keepForwarded, false);
  assert.equal(mailbox.quotaMb, 512);
  assert.equal(mailbox.messageCount, 0);
  assert.equal(mailbox.unreadCount, 0);

  const resolved = getInboundMailboxByAddress('SUPPORT@INBOUND.EXAMPLE');
  assert.equal(resolved.id, mailbox.id);
  assert.equal(resolved.userId, user.id);
  assert.equal(verifySmtpCredential('support@inbound.example', 'mailbox-pass-123').user.id, user.id);
  assert.equal(verifySmtpCredential('support@inbound.example', 'wrong-password'), null);
  assert.equal(resolveInboundRecipient('help@inbound.example').mailbox.id, mailbox.id);

  const message = createInboundMessage(resolved, {
    sender: 'alice@example.net',
    recipients: ['support@inbound.example'],
    subject: 'Hello inbound',
    messageId: '<hello@example.net>',
    rawMessage: 'From: alice@example.net\r\nTo: support@inbound.example\r\nSubject: Hello inbound\r\n\r\nHello MailHub',
    textBody: 'Hello MailHub',
    htmlBody: ''
  });
  assert.equal(message.mailboxId, mailbox.id);
  assert.equal(message.read, false);

  const mailboxes = listInboundMailboxes(user.id);
  assert.equal(mailboxes.length, 1);
  assert.equal(mailboxes[0].messageCount, 1);
  assert.equal(mailboxes[0].unreadCount, 1);

  const messages = listInboundMessages(user.id);
  assert.equal(messages.length, 1);
  assert.equal(messages[0].subject, 'Hello inbound');
  assert.equal(messages[0].preview, 'Hello MailHub');
  assert.equal('rawMessage' in messages[0], false);

  const detail = getInboundMessage(user.id, message.id);
  assert.equal(detail.rawMessage.includes('Hello MailHub'), true);
  assert.equal(detail.textBody, 'Hello MailHub');

  const readMessage = markInboundMessageRead(user.id, message.id, true);
  assert.equal(readMessage.read, true);
  assert.equal(listInboundMailboxes(user.id)[0].unreadCount, 0);
  assert.equal(markInboundMessageRead(999999, message.id, true), null);
});

test('domains can route unknown inbound recipients to catch-all targets', () => {
  initDatabase(mkdtempSync(path.join(tmpdir(), 'mailhub-inbound-catchall-')), 'inbound-secret');
  const user = createUser({ username: 'catch-user', email: 'catch@example.com', password: 'password123' });
  const domain = createDomain(user.id, {
    domain: 'catch.example',
    selector: 'mh',
    verificationToken: 'verify',
    dkimPublic: 'public',
    dkimPrivate: 'private',
    senderHost: 'mail.catch.example',
    sendingIp: '192.0.2.20',
    spfExtra: '',
    dmarcPolicy: 'none',
    dmarcRua: ''
  });
  const mailbox = createInboundMailbox(user.id, { address: 'share@catch.example' });

  const updated = updateDomain(domain.id, user.id, { catchAllAddress: 'share@catch.example' });
  assert.equal(updated.catchAllAddress, 'share@catch.example');
  const localRoute = resolveInboundRecipient('missing@catch.example');
  assert.equal(localRoute.catchAll, true);
  assert.equal(localRoute.mailbox.id, mailbox.id);
  assert.equal(localRoute.recipient, 'missing@catch.example');

  updateDomain(domain.id, user.id, { catchAllAddress: '/dev/null' });
  const dropRoute = resolveInboundRecipient('drop@catch.example');
  assert.equal(dropRoute.drop, true);
  assert.equal(dropRoute.mailbox, null);

  updateDomain(domain.id, user.id, { catchAllAddress: 'external@example.net' });
  const forwardRoute = resolveInboundRecipient('forward@catch.example');
  assert.deepEqual(forwardRoute.forwardTo, ['external@example.net']);
  assert.equal(forwardRoute.mailbox, null);
});

test('inbound mailboxes must belong to a domain owned by the user', () => {
  initDatabase(mkdtempSync(path.join(tmpdir(), 'mailhub-inbound-db-scope-')), 'inbound-secret');
  const owner = createUser({ username: 'owner-user', email: 'owner@example.com', password: 'password123' });
  const other = createUser({ username: 'other-user', email: 'other@example.com', password: 'password123' });
  createDomain(owner.id, {
    domain: 'owned.example',
    selector: 'mh',
    verificationToken: 'verify',
    dkimPublic: 'public',
    dkimPrivate: 'private',
    senderHost: 'mail.owned.example',
    sendingIp: '192.0.2.11',
    spfExtra: '',
    dmarcPolicy: 'none',
    dmarcRua: ''
  });

  assert.throws(
    () => createInboundMailbox(other.id, { address: 'support@owned.example' }),
    /收信域名不存在/
  );
});
