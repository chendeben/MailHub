import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import net from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

import {
  createDomain,
  createInboundMailbox,
  createUser,
  initDatabase,
  listInboundMessages,
  updateDomain
} from '../src/db.js';
import { sendViaSmtp } from '../src/mailer.js';
import { startSubmissionServer } from '../src/submission.js';

test('SMTP accepts unauthenticated inbound mail for local mailboxes', async () => {
  initDatabase(mkdtempSync(path.join(tmpdir(), 'mailhub-submission-inbound-')), 'inbound-secret');
  const user = createUser({ username: 'inbound-smtp', email: 'inbound-smtp@example.com', password: 'password123' });
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
  createInboundMailbox(user.id, { address: 'support@inbound.example', displayName: 'Support' });
  const [server] = startSubmissionServer({
    enabled: true,
    listeners: [{ port: 0, protocol: 'smtp' }],
    hostname: 'mx.inbound.example',
    allowInsecureAuth: true,
    inboundEnabled: true,
    relayHost: '',
    relayPort: 25,
    relaySecure: false,
    relayUsername: '',
    relayPassword: '',
    relayHelo: 'mx.inbound.example'
  });
  await waitForListening(server);

  try {
    const rawMessage = [
      'From: Alice <alice@example.net>',
      'To: Support <support@inbound.example>',
      'Subject: Hello inbound SMTP',
      'Message-ID: <hello-inbound@example.net>',
      'Content-Type: text/plain; charset=UTF-8',
      '',
      'Hello through SMTP.',
      ''
    ].join('\r\n');
    const response = await sendViaSmtp({
      host: '127.0.0.1',
      port: server.address().port,
      secure: false,
      username: '',
      password: '',
      helo: 'sender.example.net',
      mailFrom: 'alice@example.net',
      recipients: ['support@inbound.example'],
      rawMessage
    });
    assert.match(response.message, /Message accepted/i);

    const [message] = listInboundMessages(user.id);
    assert.equal(message.sender, 'alice@example.net');
    assert.deepEqual(message.recipients, ['support@inbound.example']);
    assert.equal(message.subject, 'Hello inbound SMTP');
    assert.equal(message.preview, 'Hello through SMTP.');
  } finally {
    await closeServer(server);
  }
});

test('SMTP rejects unauthenticated inbound mail for unknown recipients', async () => {
  initDatabase(mkdtempSync(path.join(tmpdir(), 'mailhub-submission-inbound-reject-')), 'inbound-secret');
  const [server] = startSubmissionServer({
    enabled: true,
    listeners: [{ port: 0, protocol: 'smtp' }],
    hostname: 'mx.inbound.example',
    allowInsecureAuth: true,
    inboundEnabled: true
  });
  await waitForListening(server);

  try {
    const transcript = await smtpTranscript(server.address().port, [
      'EHLO sender.example.net',
      'MAIL FROM:<alice@example.net>',
      'RCPT TO:<nobody@external.example>'
    ]);
    assert.match(transcript.at(-1), /^550 /);
    assert.equal(listInboundMessages(1).length, 0);
  } finally {
    await closeServer(server);
  }
});

test('SMTP authenticates with a mailbox account address and password', async () => {
  initDatabase(mkdtempSync(path.join(tmpdir(), 'mailhub-submission-mailbox-auth-')), 'inbound-secret');
  const user = createUser({ username: 'mailbox-auth', email: 'mailbox-auth@example.com', password: 'password123' });
  createDomain(user.id, {
    domain: 'authmail.example',
    selector: 'mh',
    verificationToken: 'verify',
    dkimPublic: 'public',
    dkimPrivate: 'private',
    senderHost: 'mail.authmail.example',
    sendingIp: '192.0.2.16',
    spfExtra: '',
    dmarcPolicy: 'none',
    dmarcRua: ''
  });
  createInboundMailbox(user.id, {
    address: 'admin@authmail.example',
    password: 'mailbox-pass-123'
  });
  const [server] = startSubmissionServer({
    enabled: true,
    listeners: [{ port: 0, protocol: 'smtp' }],
    hostname: 'mx.authmail.example',
    allowInsecureAuth: true,
    inboundEnabled: true
  });
  await waitForListening(server);

  try {
    const auth = Buffer.from('\u0000admin@authmail.example\u0000mailbox-pass-123').toString('base64');
    const transcript = await smtpTranscript(server.address().port, [
      'EHLO sender.example.net',
      `AUTH PLAIN ${auth}`
    ]);
    assert.match(transcript.at(-1), /^235 /);
  } finally {
    await closeServer(server);
  }
});

test('SMTP routes unknown inbound recipients to the domain catch-all mailbox', async () => {
  initDatabase(mkdtempSync(path.join(tmpdir(), 'mailhub-submission-catchall-')), 'inbound-secret');
  const user = createUser({ username: 'catchall-smtp', email: 'catchall-smtp@example.com', password: 'password123' });
  const domain = createDomain(user.id, {
    domain: 'catchall.example',
    selector: 'mh',
    verificationToken: 'verify',
    dkimPublic: 'public',
    dkimPrivate: 'private',
    senderHost: 'mail.catchall.example',
    sendingIp: '192.0.2.17',
    spfExtra: '',
    dmarcPolicy: 'none',
    dmarcRua: ''
  });
  createInboundMailbox(user.id, { address: 'share@catchall.example' });
  updateDomain(domain.id, user.id, { catchAllAddress: 'share@catchall.example' });
  const [server] = startSubmissionServer({
    enabled: true,
    listeners: [{ port: 0, protocol: 'smtp' }],
    hostname: 'mx.catchall.example',
    allowInsecureAuth: true,
    inboundEnabled: true
  });
  await waitForListening(server);

  try {
    await sendViaSmtp({
      host: '127.0.0.1',
      port: server.address().port,
      secure: false,
      username: '',
      password: '',
      helo: 'sender.example.net',
      mailFrom: 'alice@example.net',
      recipients: ['missing@catchall.example'],
      rawMessage: 'From: alice@example.net\r\nSubject: Catch all\r\n\r\nHello catch-all.'
    });

    const [message] = listInboundMessages(user.id);
    assert.equal(message.mailboxAddress, 'share@catchall.example');
    assert.deepEqual(message.recipients, ['missing@catchall.example']);
    assert.equal(message.subject, 'Catch all');
  } finally {
    await closeServer(server);
  }
});

test('SMTP forwards inbound messages without storing them when keepForwarded is false', async () => {
  initDatabase(mkdtempSync(path.join(tmpdir(), 'mailhub-submission-forward-')), 'inbound-secret');
  const relay = await startFakeSmtpServer();
  const user = createUser({ username: 'forward-smtp', email: 'forward-smtp@example.com', password: 'password123' });
  createDomain(user.id, {
    domain: 'forward.example',
    selector: 'mh',
    verificationToken: 'verify',
    dkimPublic: 'public',
    dkimPrivate: 'private',
    senderHost: 'mail.forward.example',
    sendingIp: '192.0.2.18',
    spfExtra: '',
    dmarcPolicy: 'none',
    dmarcRua: ''
  });
  createInboundMailbox(user.id, {
    address: 'ops@forward.example',
    forwardTo: 'archive@example.net',
    keepForwarded: false
  });
  const [server] = startSubmissionServer({
    enabled: true,
    listeners: [{ port: 0, protocol: 'smtp' }],
    hostname: 'mx.forward.example',
    allowInsecureAuth: true,
    inboundEnabled: true,
    relayHost: '127.0.0.1',
    relayPort: relay.port,
    relaySecure: false,
    relayUsername: '',
    relayPassword: '',
    relayHelo: 'mx.forward.example'
  });
  await waitForListening(server);

  try {
    await sendViaSmtp({
      host: '127.0.0.1',
      port: server.address().port,
      secure: false,
      username: '',
      password: '',
      helo: 'sender.example.net',
      mailFrom: 'alice@example.net',
      recipients: ['ops@forward.example'],
      rawMessage: 'From: alice@example.net\r\nSubject: Forward only\r\n\r\nForward this.'
    });

    assert.equal(listInboundMessages(user.id).length, 0);
    assert.ok(relay.commands.includes('RCPT TO:<archive@example.net>'));
    assert.match(relay.messages[0], /Subject: Forward only/);
  } finally {
    await closeServer(server);
    await relay.close();
  }
});

test('SMTP stores each inbound recipient without exposing other envelope recipients', async () => {
  initDatabase(mkdtempSync(path.join(tmpdir(), 'mailhub-submission-inbound-multi-')), 'inbound-secret');
  const supportUser = createUser({ username: 'support-user', email: 'support@example.com', password: 'password123' });
  const privateUser = createUser({ username: 'private-user', email: 'private@example.com', password: 'password123' });
  createDomain(supportUser.id, {
    domain: 'support.example',
    selector: 'mh',
    verificationToken: 'verify',
    dkimPublic: 'public',
    dkimPrivate: 'private',
    senderHost: 'mail.support.example',
    sendingIp: '192.0.2.12',
    spfExtra: '',
    dmarcPolicy: 'none',
    dmarcRua: ''
  });
  createDomain(privateUser.id, {
    domain: 'private.example',
    selector: 'mh',
    verificationToken: 'verify',
    dkimPublic: 'public',
    dkimPrivate: 'private',
    senderHost: 'mail.private.example',
    sendingIp: '192.0.2.13',
    spfExtra: '',
    dmarcPolicy: 'none',
    dmarcRua: ''
  });
  createInboundMailbox(supportUser.id, { address: 'support@support.example' });
  createInboundMailbox(privateUser.id, { address: 'private@private.example' });
  const [server] = startSubmissionServer({
    enabled: true,
    listeners: [{ port: 0, protocol: 'smtp' }],
    hostname: 'mx.inbound.example',
    allowInsecureAuth: true,
    inboundEnabled: true
  });
  await waitForListening(server);

  try {
    const rawMessage = [
      'From: Alice <alice@example.net>',
      'To: Support <support@support.example>',
      'Subject: Multi recipient',
      '',
      'Hello both.',
      ''
    ].join('\r\n');
    await sendViaSmtp({
      host: '127.0.0.1',
      port: server.address().port,
      secure: false,
      username: '',
      password: '',
      helo: 'sender.example.net',
      mailFrom: 'alice@example.net',
      recipients: ['support@support.example', 'private@private.example'],
      rawMessage
    });

    assert.deepEqual(listInboundMessages(supportUser.id)[0].recipients, ['support@support.example']);
    assert.deepEqual(listInboundMessages(privateUser.id)[0].recipients, ['private@private.example']);
  } finally {
    await closeServer(server);
  }
});

test('SMTP accepts unauthenticated inbound bounces with an empty envelope sender', async () => {
  initDatabase(mkdtempSync(path.join(tmpdir(), 'mailhub-submission-inbound-bounce-')), 'inbound-secret');
  const user = createUser({ username: 'bounce-user', email: 'bounce@example.com', password: 'password123' });
  createDomain(user.id, {
    domain: 'bounce.example',
    selector: 'mh',
    verificationToken: 'verify',
    dkimPublic: 'public',
    dkimPrivate: 'private',
    senderHost: 'mail.bounce.example',
    sendingIp: '192.0.2.14',
    spfExtra: '',
    dmarcPolicy: 'none',
    dmarcRua: ''
  });
  createInboundMailbox(user.id, { address: 'postmaster@bounce.example' });
  const [server] = startSubmissionServer({
    enabled: true,
    listeners: [{ port: 0, protocol: 'smtp' }],
    hostname: 'mx.bounce.example',
    allowInsecureAuth: true,
    inboundEnabled: true
  });
  await waitForListening(server);

  try {
    await sendViaSmtp({
      host: '127.0.0.1',
      port: server.address().port,
      secure: false,
      username: '',
      password: '',
      helo: 'sender.example.net',
      mailFrom: '',
      recipients: ['postmaster@bounce.example'],
      rawMessage: 'From: MAILER-DAEMON <>\r\nSubject: Delivery status\r\n\r\nBounced.'
    });

    const [message] = listInboundMessages(user.id);
    assert.equal(message.sender, '');
    assert.deepEqual(message.recipients, ['postmaster@bounce.example']);
  } finally {
    await closeServer(server);
  }
});

test('SMTP rejects oversized unauthenticated inbound messages without storing them', async () => {
  initDatabase(mkdtempSync(path.join(tmpdir(), 'mailhub-submission-inbound-size-')), 'inbound-secret');
  const user = createUser({ username: 'size-user', email: 'size@example.com', password: 'password123' });
  createDomain(user.id, {
    domain: 'size.example',
    selector: 'mh',
    verificationToken: 'verify',
    dkimPublic: 'public',
    dkimPrivate: 'private',
    senderHost: 'mail.size.example',
    sendingIp: '192.0.2.15',
    spfExtra: '',
    dmarcPolicy: 'none',
    dmarcRua: ''
  });
  createInboundMailbox(user.id, { address: 'support@size.example' });
  const [server] = startSubmissionServer({
    enabled: true,
    listeners: [{ port: 0, protocol: 'smtp' }],
    hostname: 'mx.size.example',
    allowInsecureAuth: true,
    inboundEnabled: true,
    maxMessageBytes: 64
  });
  await waitForListening(server);

  try {
    const transcript = await smtpTranscript(server.address().port, [
      'EHLO sender.example.net',
      'MAIL FROM:<alice@example.net>',
      'RCPT TO:<support@size.example>',
      'DATA',
      [
        'Subject: Oversized inbound',
        '',
        'This body is intentionally longer than the configured inbound message size limit.',
        '.'
      ].join('\r\n')
    ]);
    assert.match(transcript.at(-1), /^552 /);
    assert.equal(listInboundMessages(user.id).length, 0);
  } finally {
    await closeServer(server);
  }
});

function waitForListening(server) {
  if (server.listening) return Promise.resolve();
  return new Promise((resolve) => server.once('listening', resolve));
}

function closeServer(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
}

async function smtpTranscript(port, commands) {
  return await new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: '127.0.0.1', port });
    socket.setEncoding('utf8');
    socket.setTimeout(3000);
    const responses = [];
    let buffer = '';
    let index = -1;

    socket.on('data', (chunk) => {
      buffer += chunk;
      let lineEnd;
      while ((lineEnd = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, lineEnd).replace(/\r$/, '');
        buffer = buffer.slice(lineEnd + 1);
        if (!/^\d{3}[ -]/.test(line)) continue;
        responses.push(line);
        if (/^\d{3} /.test(line)) {
          index += 1;
          if (index >= commands.length) {
            socket.end('QUIT\r\n');
            resolve(responses);
            return;
          }
          socket.write(`${commands[index]}\r\n`);
        }
      }
    });
    socket.once('error', reject);
    socket.once('timeout', () => reject(new Error('SMTP transcript timed out')));
  });
}

function startFakeSmtpServer() {
  const commands = [];
  const messages = [];
  const server = net.createServer((socket) => {
    socket.setEncoding('utf8');
    socket.write('220 relay.test ESMTP ready\r\n');
    let buffer = '';
    let dataMode = false;
    let messageLines = [];
    socket.on('data', (chunk) => {
      buffer += chunk;
      let index;
      while ((index = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, index).replace(/\r$/, '');
        buffer = buffer.slice(index + 1);
        if (dataMode) {
          if (line === '.') {
            dataMode = false;
            messages.push(messageLines.join('\n'));
            messageLines = [];
            socket.write('250 2.0.0 queued as FORWARD123\r\n');
          } else {
            messageLines.push(line);
          }
          continue;
        }
        commands.push(line);
        if (line.startsWith('EHLO')) socket.write('250 relay.test\r\n');
        else if (line.startsWith('MAIL FROM') || line.startsWith('RCPT TO')) socket.write('250 ok\r\n');
        else if (line === 'DATA') {
          dataMode = true;
          socket.write('354 end with dot\r\n');
        } else if (line === 'QUIT') {
          socket.write('221 bye\r\n');
          socket.end();
        }
      }
    });
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve({
      port: server.address().port,
      commands,
      messages,
      close: () => closeServer(server)
    }));
  });
}
