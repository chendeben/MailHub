import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { test } from 'node:test';
import net from 'node:net';

test('webhook API requires authentication', async () => {
  const { child, baseUrl } = await startTestServer();

  try {
    const list = await fetch(`${baseUrl}/api/webhooks`);
    assert.equal(list.status, 401);
    assert.equal((await list.json()).error, 'Authentication required.');

    const create = await fetch(`${baseUrl}/api/webhooks`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'No auth',
        url: 'http://127.0.0.1:9/hook',
        events: ['sent']
      })
    });
    assert.equal(create.status, 401);

    const deliveries = await fetch(`${baseUrl}/api/webhook-deliveries`);
    assert.equal(deliveries.status, 401);
  } finally {
    child.kill('SIGTERM');
    await waitForExit(child, 1000);
  }
});

test('webhook API isolates users and returns secret only on create/rotate', async () => {
  const { child, baseUrl, dataDir, sessionSecret } = await startTestServer();

  try {
    seedUsers(dataDir, sessionSecret, [
      { username: 'alice', email: 'alice@example.com', password: 'password123', status: 'active' },
      { username: 'bob', email: 'bob@example.com', password: 'password123', status: 'active' }
    ]);

    const aliceCookie = await login(baseUrl, 'alice', 'password123');
    const bobCookie = await login(baseUrl, 'bob', 'password123');

    const aliceDomain = await createSendingDomain(baseUrl, aliceCookie, { domain: 'alice-hooks.example' });
    const bobDomain = await createSendingDomain(baseUrl, bobCookie, { domain: 'bob-hooks.example' });

    const create = await fetch(`${baseUrl}/api/webhooks`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: aliceCookie
      },
      body: JSON.stringify({
        name: 'Alice primary',
        url: 'http://127.0.0.1:9/alice',
        events: ['sent', 'failed'],
        enabled: true
      })
    });
    assert.equal(create.status, 201);
    const created = await create.json();
    assert.equal(created.webhook.name, 'Alice primary');
    assert.ok(created.webhook.secret);
    assert.match(created.webhook.secret, /^whsec_/);
    assert.equal(created.webhook.secretPrefix, created.webhook.secret.slice(0, 8));
    assert.deepEqual(created.webhook.events, ['sent', 'failed']);
    assert.equal(created.webhook.domainId, null);
    assert.equal(created.webhook.enabled, true);
    const aliceWebhookId = created.webhook.id;
    const firstSecret = created.webhook.secret;

    const bobCreate = await fetch(`${baseUrl}/api/webhooks`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: bobCookie
      },
      body: JSON.stringify({
        name: 'Bob primary',
        url: 'http://127.0.0.1:9/bob',
        events: ['bounced'],
        domainId: bobDomain.id
      })
    });
    assert.equal(bobCreate.status, 201);
    const bobWebhook = (await bobCreate.json()).webhook;
    assert.equal(bobWebhook.domainId, bobDomain.id);
    assert.ok(bobWebhook.secret);

    const aliceList = await fetch(`${baseUrl}/api/webhooks`, {
      headers: { Cookie: aliceCookie }
    });
    assert.equal(aliceList.status, 200);
    const aliceListBody = await aliceList.json();
    assert.equal(aliceListBody.webhooks.length, 1);
    assert.equal(aliceListBody.webhooks[0].id, aliceWebhookId);
    assert.equal('secret' in aliceListBody.webhooks[0], false);
    assert.equal(aliceListBody.webhooks[0].secretPrefix, firstSecret.slice(0, 8));

    const bobSeesAlice = await fetch(`${baseUrl}/api/webhooks`, {
      headers: { Cookie: bobCookie }
    });
    assert.equal(bobSeesAlice.status, 200);
    const bobList = await bobSeesAlice.json();
    assert.equal(bobList.webhooks.length, 1);
    assert.equal(bobList.webhooks[0].id, bobWebhook.id);
    assert.equal(bobList.webhooks[0].name, 'Bob primary');
    assert.equal('secret' in bobList.webhooks[0], false);

    const bobPatchAlice = await fetch(`${baseUrl}/api/webhooks/${aliceWebhookId}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Cookie: bobCookie
      },
      body: JSON.stringify({ name: 'Hijacked' })
    });
    assert.equal(bobPatchAlice.status, 404);

    const bobDeleteAlice = await fetch(`${baseUrl}/api/webhooks/${aliceWebhookId}`, {
      method: 'DELETE',
      headers: { Cookie: bobCookie }
    });
    assert.equal(bobDeleteAlice.status, 404);

    const bobRotateAlice = await fetch(`${baseUrl}/api/webhooks/${aliceWebhookId}/rotate-secret`, {
      method: 'POST',
      headers: { Cookie: bobCookie }
    });
    assert.equal(bobRotateAlice.status, 404);

    const bobTestAlice = await fetch(`${baseUrl}/api/webhooks/${aliceWebhookId}/test`, {
      method: 'POST',
      headers: { Cookie: bobCookie }
    });
    assert.equal(bobTestAlice.status, 404);

    const stealDomain = await fetch(`${baseUrl}/api/webhooks`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: aliceCookie
      },
      body: JSON.stringify({
        name: 'Steal bob domain',
        url: 'http://127.0.0.1:9/steal',
        events: ['sent'],
        domainId: bobDomain.id
      })
    });
    assert.equal(stealDomain.status, 400);
    assert.match((await stealDomain.json()).error, /域名/);

    const domainScoped = await fetch(`${baseUrl}/api/webhooks`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: aliceCookie
      },
      body: JSON.stringify({
        name: 'Alice domain',
        url: 'http://127.0.0.1:9/alice-domain',
        events: ['failed'],
        domainId: aliceDomain.id
      })
    });
    assert.equal(domainScoped.status, 201);
    assert.equal((await domainScoped.json()).webhook.domainId, aliceDomain.id);

    const filtered = await fetch(`${baseUrl}/api/webhooks?domainId=${aliceDomain.id}`, {
      headers: { Cookie: aliceCookie }
    });
    assert.equal(filtered.status, 200);
    const filteredBody = await filtered.json();
    assert.equal(filteredBody.webhooks.length, 1);
    assert.equal(filteredBody.webhooks[0].name, 'Alice domain');

    const accountOnly = await fetch(`${baseUrl}/api/webhooks?domainId=null`, {
      headers: { Cookie: aliceCookie }
    });
    assert.equal(accountOnly.status, 200);
    const accountOnlyBody = await accountOnly.json();
    assert.equal(accountOnlyBody.webhooks.length, 1);
    assert.equal(accountOnlyBody.webhooks[0].name, 'Alice primary');

    const patch = await fetch(`${baseUrl}/api/webhooks/${aliceWebhookId}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Cookie: aliceCookie
      },
      body: JSON.stringify({
        name: 'Alice renamed',
        events: ['sent'],
        enabled: false
      })
    });
    assert.equal(patch.status, 200);
    const patched = await patch.json();
    assert.equal(patched.webhook.name, 'Alice renamed');
    assert.deepEqual(patched.webhook.events, ['sent']);
    assert.equal(patched.webhook.enabled, false);
    assert.equal('secret' in patched.webhook, false);

    const rotate = await fetch(`${baseUrl}/api/webhooks/${aliceWebhookId}/rotate-secret`, {
      method: 'POST',
      headers: { Cookie: aliceCookie }
    });
    assert.equal(rotate.status, 200);
    const rotated = await rotate.json();
    assert.ok(rotated.webhook.secret);
    assert.notEqual(rotated.webhook.secret, firstSecret);
    assert.equal(rotated.webhook.secretPrefix, rotated.webhook.secret.slice(0, 8));

    const afterRotateList = await fetch(`${baseUrl}/api/webhooks?domainId=null`, {
      headers: { Cookie: aliceCookie }
    });
    assert.equal('secret' in (await afterRotateList.json()).webhooks[0], false);

    const invalidEvents = await fetch(`${baseUrl}/api/webhooks`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: aliceCookie
      },
      body: JSON.stringify({
        name: 'Bad events',
        url: 'http://127.0.0.1:9/bad',
        events: ['queued']
      })
    });
    assert.equal(invalidEvents.status, 400);

    const insecureUrl = await fetch(`${baseUrl}/api/webhooks`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: aliceCookie
      },
      body: JSON.stringify({
        name: 'Bad url',
        url: 'http://example.com/hook',
        events: ['sent']
      })
    });
    assert.equal(insecureUrl.status, 400);
  } finally {
    child.kill('SIGTERM');
    await waitForExit(child, 1000);
  }
});

test('webhook test and replay endpoints work', async () => {
  const { child, baseUrl } = await startTestServer();

  try {
    const cookie = await login(baseUrl, 'admin', 'password123');
    await createSendingDomain(baseUrl, cookie, { domain: 'webhook-test.example' });

    const create = await fetch(`${baseUrl}/api/webhooks`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: cookie
      },
      body: JSON.stringify({
        name: 'Test endpoint',
        url: 'http://127.0.0.1:9/test',
        events: ['sent', 'bounced']
      })
    });
    assert.equal(create.status, 201);
    const webhook = (await create.json()).webhook;

    const testDelivery = await fetch(`${baseUrl}/api/webhooks/${webhook.id}/test`, {
      method: 'POST',
      headers: { Cookie: cookie }
    });
    assert.equal(testDelivery.status, 202);
    const testBody = await testDelivery.json();
    assert.ok(testBody.delivery);
    assert.equal(testBody.delivery.webhookId, webhook.id);
    assert.equal(testBody.delivery.sendEventId, 0);
    assert.equal(testBody.delivery.eventType, 'sent');
    assert.equal(testBody.delivery.status, 'pending');
    assert.equal(testBody.delivery.attemptCount, 0);
    const payload = JSON.parse(testBody.delivery.payloadJson);
    assert.equal(payload.data.test, true);
    assert.equal(payload.data.message_id, 'mh-test');
    assert.equal(payload.type, 'email.sent');
    const deliveryId = testBody.delivery.id;

    const listDeliveries = await fetch(`${baseUrl}/api/webhook-deliveries?webhookId=${webhook.id}`, {
      headers: { Cookie: cookie }
    });
    assert.equal(listDeliveries.status, 200);
    const listed = await listDeliveries.json();
    assert.equal(listed.deliveries.length, 1);
    assert.equal(listed.deliveries[0].id, deliveryId);

    const replay = await fetch(`${baseUrl}/api/webhook-deliveries/${deliveryId}/replay`, {
      method: 'POST',
      headers: { Cookie: cookie }
    });
    assert.equal(replay.status, 200);
    const replayed = await replay.json();
    assert.equal(replayed.delivery.id, deliveryId);
    assert.equal(replayed.delivery.status, 'pending');
    assert.equal(replayed.delivery.attemptCount, 0);
    assert.equal(JSON.parse(replayed.delivery.payloadJson).id, `whd_${deliveryId}`);

    const retest = await fetch(`${baseUrl}/api/webhooks/${webhook.id}/test`, {
      method: 'POST',
      headers: { Cookie: cookie }
    });
    assert.equal(retest.status, 202);
    const retested = await retest.json();
    assert.equal(retested.delivery.id, deliveryId);
    assert.equal(retested.delivery.status, 'pending');

    const allDeliveries = await fetch(`${baseUrl}/api/webhook-deliveries`, {
      headers: { Cookie: cookie }
    });
    assert.equal(allDeliveries.status, 200);
    assert.ok((await allDeliveries.json()).deliveries.length >= 1);
  } finally {
    child.kill('SIGTERM');
    await waitForExit(child, 1000);
  }
});

test('webhook delivery replay is isolated by user', async () => {
  const { child, baseUrl, dataDir, sessionSecret } = await startTestServer();

  try {
    seedUsers(dataDir, sessionSecret, [
      { username: 'carol', email: 'carol@example.com', password: 'password123', status: 'active' },
      { username: 'dave', email: 'dave@example.com', password: 'password123', status: 'active' }
    ]);

    const carolCookie = await login(baseUrl, 'carol', 'password123');
    const daveCookie = await login(baseUrl, 'dave', 'password123');

    const create = await fetch(`${baseUrl}/api/webhooks`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: carolCookie
      },
      body: JSON.stringify({
        name: 'Carol hook',
        url: 'http://127.0.0.1:9/carol',
        events: ['failed']
      })
    });
    assert.equal(create.status, 201);
    const webhook = (await create.json()).webhook;

    const testDelivery = await fetch(`${baseUrl}/api/webhooks/${webhook.id}/test`, {
      method: 'POST',
      headers: { Cookie: carolCookie }
    });
    assert.equal(testDelivery.status, 202);
    const deliveryId = (await testDelivery.json()).delivery.id;

    const daveList = await fetch(`${baseUrl}/api/webhook-deliveries`, {
      headers: { Cookie: daveCookie }
    });
    assert.equal(daveList.status, 200);
    assert.equal((await daveList.json()).deliveries.length, 0);

    const daveReplay = await fetch(`${baseUrl}/api/webhook-deliveries/${deliveryId}/replay`, {
      method: 'POST',
      headers: { Cookie: daveCookie }
    });
    assert.equal(daveReplay.status, 404);

    const deleted = await fetch(`${baseUrl}/api/webhooks/${webhook.id}`, {
      method: 'DELETE',
      headers: { Cookie: carolCookie }
    });
    assert.equal(deleted.status, 200);
    assert.equal((await deleted.json()).deleted, true);

    const missing = await fetch(`${baseUrl}/api/webhooks/${webhook.id}/test`, {
      method: 'POST',
      headers: { Cookie: carolCookie }
    });
    assert.equal(missing.status, 404);
  } finally {
    child.kill('SIGTERM');
    await waitForExit(child, 1000);
  }
});

async function startTestServer() {
  const port = await freePort();
  const dataDir = mkdtempSync(path.join(tmpdir(), 'mailhub-webhooks-api-'));
  const sessionSecret = 'test-session-secret-webhooks';
  const child = spawn(process.execPath, ['src/server.js'], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      PORT: String(port),
      DATA_DIR: dataDir,
      ADMIN_PASSWORD: 'password123',
      SESSION_SECRET: sessionSecret,
      DNS_AUTO_CHECK_ENABLED: 'false',
      SUBMISSION_ENABLED: 'false',
      WEBHOOK_WORKER_ENABLED: '0',
      WEBHOOK_ALLOW_HTTP_LOCAL: '1',
      DELIVERY_TRACKING_ENABLED: 'false'
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  await waitForOutput(child, 'MailHub listening');
  return { child, baseUrl: `http://127.0.0.1:${port}`, dataDir, sessionSecret };
}

async function login(baseUrl, username, password) {
  const response = await fetch(`${baseUrl}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  assert.equal(response.status, 200);
  const cookie = response.headers.get('set-cookie')?.split(';')[0] || '';
  assert.ok(cookie);
  return cookie;
}

function seedUsers(dataDir, sessionSecret, users) {
  const script = `
    import { initDatabase, createUser } from './src/db.js';

    initDatabase(process.env.DATA_DIR, process.env.SESSION_SECRET);
    for (const user of JSON.parse(process.env.SEED_USERS)) {
      createUser(user);
    }
  `;
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      DATA_DIR: dataDir,
      SESSION_SECRET: sessionSecret,
      SEED_USERS: JSON.stringify(users)
    },
    encoding: 'utf8'
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
}

async function createSendingDomain(baseUrl, cookie, data = {}) {
  const domain = data.domain || 'send.example';
  const response = await fetch(`${baseUrl}/api/domains`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Cookie: cookie
    },
    body: JSON.stringify({
      domain,
      selector: data.selector || 'mh',
      senderHost: data.senderHost || `mail.${domain}`,
      sendingIp: data.sendingIp || '127.0.0.1'
    })
  });
  assert.equal(response.status, 201);
  return (await response.json()).domain;
}

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
