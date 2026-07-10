import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import net from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

import {
  createDomain,
  createSendEvent,
  createTrackingLink,
  createUser,
  getSendEvent,
  initDatabase
} from '../src/db.js';
import {
  createTrackingToken,
  encryptTrackingTarget,
  hashTrackingToken
} from '../src/tracking.js';

test('serves neutral open pixels and only records valid GET requests', async () => {
  const fixture = await trackingServerFixture();
  try {
    const head = await fetch(`${fixture.baseUrl}/t/o/${fixture.openToken}.gif`, {
      method: 'HEAD',
      headers: { 'User-Agent': 'Mozilla/5.0' }
    });
    assert.equal(head.status, 200);
    assert.match(head.headers.get('content-type') || '', /image\/gif/i);
    assert.match(head.headers.get('cache-control') || '', /no-store/i);
    assert.equal(getSendEvent(fixture.userId, fixture.eventId).tracking.events.length, 0);

    const open = await fetch(`${fixture.baseUrl}/t/o/${fixture.openToken}.gif`, {
      headers: {
        'User-Agent': 'Mozilla/5.0',
        'X-Forwarded-For': '203.0.113.7'
      }
    });
    assert.equal(open.status, 200);
    assert.match(open.headers.get('content-type') || '', /image\/gif/i);
    assert.ok((await open.arrayBuffer()).byteLength > 0);
    const detail = getSendEvent(fixture.userId, fixture.eventId);
    assert.equal(detail.tracking.summary.totalOpens, 1);
    assert.equal(detail.tracking.events[0].source, 'direct');

    const unknown = await fetch(`${fixture.baseUrl}/t/o/${createTrackingToken()}.gif`);
    assert.equal(unknown.status, 200);
    assert.equal(await unknown.arrayBuffer().then((value) => value.byteLength), 42);
    const malformed = await fetch(`${fixture.baseUrl}/t/o/bad.gif`, { redirect: 'manual' });
    assert.equal(malformed.status, 200);
    assert.match(malformed.headers.get('content-type') || '', /image\/gif/i);
    assert.equal(malformed.headers.get('location'), null);
  } finally {
    fixture.child.kill('SIGTERM');
    await waitForExit(fixture.child, 1000);
  }
});

test('redirects opaque click tokens and rejects unknown or unreadable targets', async () => {
  const fixture = await trackingServerFixture();
  try {
    const click = await fetch(`${fixture.baseUrl}/t/c/${fixture.clickToken}`, {
      redirect: 'manual',
      headers: { 'User-Agent': 'Mozilla/5.0' }
    });
    assert.equal(click.status, 302);
    assert.equal(click.headers.get('location'), fixture.target);
    assert.match(click.headers.get('cache-control') || '', /no-store/i);
    assert.equal(click.headers.get('referrer-policy'), 'no-referrer');
    const detail = getSendEvent(fixture.userId, fixture.eventId);
    assert.equal(detail.tracking.summary.totalClicks, 1);
    assert.equal(detail.tracking.events.find((event) => event.eventType === 'click').targetOrigin, 'https://example.net');

    const unknown = await fetch(`${fixture.baseUrl}/t/c/${createTrackingToken()}`, { redirect: 'manual' });
    assert.equal(unknown.status, 404);
    assert.equal(unknown.headers.get('location'), null);
    const malformed = await fetch(`${fixture.baseUrl}/t/c/bad?u=https://attacker.example`, { redirect: 'manual' });
    assert.equal(malformed.status, 404);
    assert.equal(malformed.headers.get('location'), null);

    const unreadable = await fetch(`${fixture.baseUrl}/t/c/${fixture.unreadableClickToken}`, { redirect: 'manual' });
    assert.equal(unreadable.status, 410);
    assert.equal(unreadable.headers.get('location'), null);
  } finally {
    fixture.child.kill('SIGTERM');
    await waitForExit(fixture.child, 1000);
  }
});

async function trackingServerFixture() {
  const dataDir = mkdtempSync(path.join(tmpdir(), 'mailhub-tracking-server-'));
  initDatabase(dataDir, 'session-secret');
  const user = createUser({ username: `tracking-${Date.now()}`, email: `tracking-${Date.now()}@example.com`, password: 'password123' });
  const domain = createDomain(user.id, domainFixture(`tracking-${Date.now()}.example`));
  const openToken = createTrackingToken();
  const eventId = createSendEvent({
    userId: user.id,
    domainId: domain.id,
    sender: `sender@${domain.domain}`,
    recipients: ['reader@example.net'],
    subject: 'Tracking endpoint',
    status: 'sent',
    trackingToken: openToken,
    trackingOpens: true,
    trackingClicks: true
  });
  const target = 'https://example.net/reset?token=private#account';
  const clickToken = createTrackingToken();
  createTrackingLink(user.id, eventId, {
    token: clickToken,
    targetCiphertext: encryptTrackingTarget(target, 'tracking-secret'),
    targetFingerprint: hashTrackingToken(target),
    targetOrigin: 'https://example.net'
  });
  const unreadableClickToken = createTrackingToken();
  createTrackingLink(user.id, eventId, {
    token: unreadableClickToken,
    targetCiphertext: encryptTrackingTarget('https://example.net/old', 'old-secret'),
    targetFingerprint: hashTrackingToken('https://example.net/old'),
    targetOrigin: 'https://example.net'
  });

  const port = await freePort();
  const child = spawn(process.execPath, ['src/server.js'], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      PORT: String(port),
      DATA_DIR: dataDir,
      ADMIN_PASSWORD: 'password123',
      SESSION_SECRET: 'session-secret',
      TRACKING_SECRET: 'tracking-secret',
      TRUST_PROXY: 'true',
      SUBMISSION_ENABLED: 'false',
      WEBHOOK_WORKER_ENABLED: '0',
      DNS_AUTO_CHECK_ENABLED: 'false',
      DELIVERY_TRACKING_ENABLED: 'false'
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  await waitForOutput(child, 'MailHub listening');
  return {
    child,
    baseUrl: `http://127.0.0.1:${port}`,
    userId: user.id,
    eventId,
    openToken,
    clickToken,
    unreadableClickToken,
    target
  };
}

function domainFixture(domain) {
  return {
    domain,
    selector: 'mh',
    verificationToken: 'verify',
    dkimPublic: 'public',
    dkimPrivate: 'private',
    senderHost: `mail.${domain}`,
    sendingIp: '192.0.2.10',
    spfExtra: '',
    dmarcPolicy: 'none',
    dmarcRua: ''
  };
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
