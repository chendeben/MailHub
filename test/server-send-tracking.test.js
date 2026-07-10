import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import net from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

test('instruments tracked API HTML before DKIM and supports per-send opt-out', async () => {
  const relay = await startFakeSmtpServer();
  const port = await freePort();
  const dataDir = mkdtempSync(path.join(tmpdir(), 'mailhub-send-tracking-'));
  const child = spawn(process.execPath, ['src/server.js'], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      PORT: String(port),
      DATA_DIR: dataDir,
      APP_BASE_URL: `http://127.0.0.1:${port}`,
      ADMIN_PASSWORD: 'password123',
      SESSION_SECRET: 'session-secret',
      TRACKING_SECRET: 'tracking-secret',
      SMTP_HOST: '127.0.0.1',
      SMTP_PORT: String(relay.port),
      SMTP_HELO: 'mail.track-send.example',
      SEND_REQUIRES_VERIFIED: 'false',
      SUBMISSION_ENABLED: 'false',
      WEBHOOK_WORKER_ENABLED: '0',
      DNS_AUTO_CHECK_ENABLED: 'false',
      DELIVERY_TRACKING_ENABLED: 'false'
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });

  try {
    await waitForOutput(child, 'MailHub listening');
    const baseUrl = `http://127.0.0.1:${port}`;
    const cookie = await login(baseUrl);
    const domainResponse = await fetch(`${baseUrl}/api/domains`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: cookie },
      body: JSON.stringify({ domain: 'track-send.example' })
    });
    assert.equal(domainResponse.status, 201);

    const settings = await fetch(`${baseUrl}/api/admin/settings`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', Cookie: cookie },
      body: JSON.stringify({ engagementTrackingEnabled: true })
    });
    assert.equal(settings.status, 200);
    assert.equal((await settings.json()).settings.engagementTrackingEnabled, true);

    const tracked = await sendHtml(baseUrl, cookie, {
      subject: 'Tracked HTML',
      html: '<html><body><a href="https://example.net/reset?token=secret">Reset</a></body></html>'
    });
    assert.equal(tracked.eventId > 0, true);
    assert.deepEqual(tracked.tracking, { enabled: true, opens: true, clicks: true, messageLevel: false });
    await waitFor(() => relay.messages.length === 1);
    const trackedMessage = relay.messages[0];
    assert.match(trackedMessage, /^DKIM-Signature:/m);
    const trackedHtml = decodeHtmlPart(trackedMessage);
    assert.match(trackedHtml, new RegExp(`${escapeRegExp(baseUrl)}/t/o/[A-Za-z0-9_-]+\\.gif`));
    assert.match(trackedHtml, new RegExp(`${escapeRegExp(baseUrl)}/t/c/[A-Za-z0-9_-]+`));
    assert.equal(trackedHtml.includes('token=secret'), false);

    const optedOut = await sendHtml(baseUrl, cookie, {
      subject: 'Untracked HTML',
      html: '<a href="https://example.net/private">Private</a>',
      tracking: { opens: false, clicks: false }
    });
    assert.deepEqual(optedOut.tracking, { enabled: false, opens: false, clicks: false, messageLevel: false });
    await waitFor(() => relay.messages.length === 2);
    const untrackedHtml = decodeHtmlPart(relay.messages[1]);
    assert.match(untrackedHtml, /https:\/\/example\.net\/private/);
    assert.equal(untrackedHtml.includes('/t/o/'), false);
    assert.equal(untrackedHtml.includes('/t/c/'), false);

    const noTrackableLinks = await sendHtml(baseUrl, cookie, {
      subject: 'No trackable links',
      html: '<p>No links here.</p>',
      tracking: { opens: false, clicks: true }
    });
    assert.deepEqual(noTrackableLinks.tracking, { enabled: false, opens: false, clicks: false, messageLevel: false });
    await waitFor(() => relay.messages.length === 3);
    const noTrackableLinksHtml = decodeHtmlPart(relay.messages[2]);
    assert.equal(noTrackableLinksHtml.includes('/t/c/'), false);

    const events = await fetch(`${baseUrl}/api/events`, { headers: { Cookie: cookie } }).then((response) => response.json());
    assert.equal(events.events.length, 3);
    assert.equal(events.events.every((event) => event.status === 'queued'), true);
    assert.equal(events.events.find((event) => event.subject === 'Tracked HTML').tracking.enabled, true);
    assert.equal(events.events.find((event) => event.subject === 'No trackable links').tracking.enabled, false);
  } finally {
    child.kill('SIGTERM');
    await waitForExit(child, 1000);
    await relay.close();
  }
});

async function sendHtml(baseUrl, cookie, data) {
  const response = await fetch(`${baseUrl}/api/send`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: cookie },
    body: JSON.stringify({
      from: 'noreply@track-send.example',
      to: 'reader@example.net',
      text: 'Fallback',
      ...data
    })
  });
  assert.equal(response.status, 202);
  return response.json();
}

async function login(baseUrl) {
  const response = await fetch(`${baseUrl}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'admin', password: 'password123' })
  });
  assert.equal(response.status, 200);
  return response.headers.get('set-cookie')?.split(';')[0] || '';
}

function decodeHtmlPart(rawMessage) {
  const match = rawMessage.match(/Content-Type: text\/html[^]*?\n\n([A-Za-z0-9+/=\n]+?)(?:\n--|$)/i);
  assert.ok(match, 'expected an HTML MIME part');
  return Buffer.from(match[1].replace(/\s+/g, ''), 'base64').toString('utf8');
}

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
            socket.write('250 2.0.0 queued as TRACK123\r\n');
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
      close: () => new Promise((closeResolve) => server.close(closeResolve))
    }));
  });
}

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close((error) => (error ? reject(error) : resolve(port)));
    });
    server.on('error', reject);
  });
}

async function waitFor(predicate, timeoutMs = 5000) {
  const startedAt = Date.now();
  while (!predicate()) {
    if (Date.now() - startedAt > timeoutMs) throw new Error('Timed out waiting for SMTP message.');
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

function waitForOutput(child, value, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    let buffer = '';
    const timer = setTimeout(() => reject(new Error(`Timed out waiting for ${value}\n${buffer}`)), timeoutMs);
    const onData = (chunk) => {
      buffer += String(chunk);
      if (!buffer.includes(value)) return;
      clearTimeout(timer);
      child.stdout?.off('data', onData);
      child.stderr?.off('data', onData);
      resolve();
    };
    child.stdout?.on('data', onData);
    child.stderr?.on('data', onData);
  });
}

function waitForExit(child, timeoutMs) {
  return new Promise((resolve) => {
    if (child.exitCode != null) return resolve(true);
    const timer = setTimeout(() => resolve(false), timeoutMs);
    child.once('exit', () => {
      clearTimeout(timer);
      resolve(true);
    });
  });
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
