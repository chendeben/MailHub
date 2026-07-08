import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { test } from 'node:test';
import net from 'node:net';

test('admin API routes respond once and keep the server alive', async () => {
  const port = await freePort();
  const child = spawn(process.execPath, ['src/server.js'], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      PORT: String(port),
      DATA_DIR: mkdtempSync(path.join(tmpdir(), 'mailhub-server-test-')),
      ADMIN_PASSWORD: 'password123',
      SUBMISSION_ENABLED: 'false'
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });

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

    const settings = await fetch(`${baseUrl}/api/admin/settings`, {
      headers: { Cookie: cookie }
    });
    assert.equal(settings.status, 200);
    assert.equal((await settings.json()).settings.mailHostname, 'mailhub.local');

    const exited = await waitForExit(child, 300);
    assert.equal(exited, false);
  } finally {
    child.kill('SIGTERM');
    await waitForExit(child, 1000);
  }
});

test('built auth assets are served before authentication', async () => {
  const assetName = readdirSync(path.join(process.cwd(), 'public', 'assets')).find((name) => /\.(js|css)$/.test(name));
  assert.ok(assetName, 'expected at least one built frontend asset');

  const port = await freePort();
  const child = spawn(process.execPath, ['src/server.js'], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      PORT: String(port),
      DATA_DIR: mkdtempSync(path.join(tmpdir(), 'mailhub-server-test-')),
      ADMIN_PASSWORD: 'password123',
      SUBMISSION_ENABLED: 'false'
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });

  try {
    await waitForOutput(child, 'MailHub listening');
    const baseUrl = `http://127.0.0.1:${port}`;

    const login = await fetch(`${baseUrl}/login`);
    assert.equal(login.status, 200);

    const asset = await fetch(`${baseUrl}/assets/${assetName}`, { redirect: 'manual' });
    assert.equal(asset.status, 200);
    assert.notEqual(asset.headers.get('location'), '/login');
  } finally {
    child.kill('SIGTERM');
    await waitForExit(child, 1000);
  }
});

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      server.close(() => {
        if (address && typeof address === 'object') resolve(address.port);
        else reject(new Error('Unable to allocate a test port.'));
      });
    });
  });
}

function waitForOutput(child, text) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error(`Timed out waiting for ${text}`)), 5000);
    const chunks = [];
    const onData = (chunk) => {
      chunks.push(String(chunk));
      if (chunks.join('').includes(text)) {
        clearTimeout(timeout);
        child.stdout.off('data', onData);
        child.stderr.off('data', onData);
        resolve();
      }
    };
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    child.once('exit', (code) => {
      clearTimeout(timeout);
      reject(new Error(`Server exited early with code ${code}: ${chunks.join('')}`));
    });
  });
}

function waitForExit(child, timeoutMs) {
  if (child.exitCode !== null) return Promise.resolve(true);
  return new Promise((resolve) => {
    const timeout = setTimeout(() => {
      child.off('exit', onExit);
      resolve(false);
    }, timeoutMs);
    const onExit = () => {
      clearTimeout(timeout);
      resolve(true);
    };
    child.once('exit', onExit);
  });
}
