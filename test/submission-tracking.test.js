import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import net from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

import {
  createDomain,
  createUser,
  initDatabase,
  listSendEvents,
  saveSmtpCredential
} from '../src/db.js';
import { createDkimKeyPair } from '../src/dkim.js';
import { sendViaSmtp } from '../src/mailer.js';
import { startSubmissionServer } from '../src/submission.js';

test('SMTP submission instruments HTML before DKIM and relays one tracked message', async () => {
  initDatabase(mkdtempSync(path.join(tmpdir(), 'mailhub-submission-tracking-')), 'session-secret');
  const user = createUser({ username: 'submission-user', email: 'submission-user@example.com', password: 'password123' });
  saveSmtpCredential(user.id, { username: 'smtp-submission-user', password: 'smtp-password' });
  const keys = createDkimKeyPair();
  createDomain(user.id, {
    domain: 'submission-track.example',
    selector: 'mh202607',
    verificationToken: 'verify',
    dkimPublic: keys.publicKey,
    dkimPrivate: keys.privateKey,
    senderHost: 'mail.submission-track.example',
    sendingIp: '192.0.2.10',
    spfExtra: '',
    dmarcPolicy: 'none',
    dmarcRua: ''
  });
  const relay = await startFakeSmtpServer();
  const [submission] = startSubmissionServer({
    enabled: true,
    listeners: [{ port: 0, protocol: 'smtp' }],
    hostname: 'submission-track.example',
    allowInsecureAuth: true,
    relayHost: '127.0.0.1',
    relayPort: relay.port,
    relaySecure: false,
    relayUsername: '',
    relayPassword: '',
    relayHelo: 'mail.submission-track.example',
    getTrackingSettings: () => ({
      enabled: false,
      appBaseUrl: 'https://mail.example.com',
      secret: 'tracking-secret'
    })
  });
  await waitForListening(submission);

  try {
    const rawMessage = [
      'From: noreply@submission-track.example',
      'To: reader@example.net',
      'Subject: Submission tracked',
      'MIME-Version: 1.0',
      'X-MailHub-Track: opens,clicks',
      'Content-Type: text/html; charset=UTF-8',
      '',
      '<html><body><a href="https://example.net/private?token=secret">Open</a></body></html>',
      ''
    ].join('\r\n');
    const response = await sendViaSmtp({
      host: '127.0.0.1',
      port: submission.address().port,
      secure: false,
      username: 'smtp-submission-user',
      password: 'smtp-password',
      helo: 'client.example',
      mailFrom: 'noreply@submission-track.example',
      recipients: ['reader@example.net'],
      rawMessage
    });
    assert.match(response.message, /Message queued/i);
    await waitFor(() => relay.messages.length === 1);

    const relayed = relay.messages[0];
    assert.match(relayed, /^DKIM-Signature:/m);
    assert.doesNotMatch(relayed, /^X-MailHub-Track:/im);
    const decoded = relayed.replace(/=\n/g, '').replace(/=3D/gi, '=');
    assert.match(decoded, /https:\/\/mail\.example\.com\/t\/o\/[A-Za-z0-9_-]+\.gif/);
    assert.match(decoded, /https:\/\/mail\.example\.com\/t\/c\/[A-Za-z0-9_-]+/);
    assert.equal(decoded.includes('token=secret'), false);

    const [event] = listSendEvents(user.id);
    assert.equal(event.status, 'queued');
    assert.equal(event.tracking.opens, true);
    assert.equal(event.tracking.clicks, true);
    assert.equal(event.tracking.messageLevel, false);
  } finally {
    await closeServer(submission);
    await relay.close();
  }
});

function startFakeSmtpServer() {
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
            socket.write('250 2.0.0 queued as SUBTRACK123\r\n');
          } else {
            messageLines.push(line);
          }
          continue;
        }
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
      messages,
      close: () => closeServer(server)
    }));
  });
}

function waitForListening(server) {
  if (server.listening) return Promise.resolve();
  return new Promise((resolve) => server.once('listening', resolve));
}

function closeServer(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
}

async function waitFor(predicate, timeoutMs = 5000) {
  const startedAt = Date.now();
  while (!predicate()) {
    if (Date.now() - startedAt > timeoutMs) throw new Error('Timed out waiting for relayed message.');
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}
