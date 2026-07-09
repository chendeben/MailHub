import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import net from 'node:net';

test('anonymous root serves landing page with no-store cache header', async () => {
  ensureLandingArtifact();
  const port = await freePort();
  const child = spawnServer(port);
  try {
    await waitForOutput(child, 'MailHub listening');
    const response = await fetch(`http://127.0.0.1:${port}/`);
    assert.equal(response.status, 200);
    assert.match(response.headers.get('cache-control') || '', /no-store/i);
    const html = await response.text();
    assert.match(html, /MailHub/i);
    assert.match(html, /data-i18n|hero|Get started|开始使用|landing/i);
    assert.doesNotMatch(html, /id="root"/);
  } finally {
    child.kill('SIGTERM');
    await waitForExit(child, 1000);
  }
});

test('authenticated root serves admin app shell', async () => {
  ensureLandingArtifact();
  const port = await freePort();
  const child = spawnServer(port);
  try {
    await waitForOutput(child, 'MailHub listening');
    const baseUrl = `http://127.0.0.1:${port}`;
    const login = await fetch(`${baseUrl}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'password123' })
    });
    assert.equal(login.status, 200);
    const cookie = login.headers.get('set-cookie')?.split(';')[0] || '';
    assert.ok(cookie);

    const response = await fetch(`${baseUrl}/`, { headers: { Cookie: cookie } });
    assert.equal(response.status, 200);
    assert.match(response.headers.get('cache-control') || '', /no-store/i);
    const html = await response.text();
    assert.match(html, /id="root"/);
  } finally {
    child.kill('SIGTERM');
    await waitForExit(child, 1000);
  }
});

test('landing.html is publicly reachable without auth', async () => {
  ensureLandingArtifact();
  const port = await freePort();
  const child = spawnServer(port);
  try {
    await waitForOutput(child, 'MailHub listening');
    const response = await fetch(`http://127.0.0.1:${port}/landing.html`);
    assert.equal(response.status, 200);
    assert.notEqual(response.headers.get('location'), '/login');
  } finally {
    child.kill('SIGTERM');
    await waitForExit(child, 1000);
  }
});

function ensureLandingArtifact() {
  const landingPath = path.join(process.cwd(), 'public', 'landing.html');
  if (existsSync(landingPath)) return;
  writeFileSync(landingPath, '<!doctype html><html><body><h1>MailHub Landing</h1><div data-i18n="hero.title">Get started</div></body></html>');
}

function spawnServer(port) {
  return spawn(process.execPath, ['src/server.js'], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      PORT: String(port),
      DATA_DIR: mkdtempSync(path.join(tmpdir(), 'mailhub-landing-test-')),
      ADMIN_PASSWORD: 'password123',
      SUBMISSION_ENABLED: 'false',
      WEBHOOK_WORKER_ENABLED: '0'
    },
    stdio: ['ignore', 'pipe', 'pipe']
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

function waitForOutput(child, text, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    let buffer = '';
    const timer = setTimeout(() => reject(new Error(`Timed out waiting for: ${text}\n${buffer}`)), timeoutMs);
    const onData = (chunk) => {
      buffer += String(chunk);
      if (buffer.includes(text)) {
        clearTimeout(timer);
        child.stdout?.off('data', onData);
        child.stderr?.off('data', onData);
        resolve();
      }
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
