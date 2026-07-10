import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
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
    const settingsPayload = await settings.json();
    assert.equal(settingsPayload.settings.mailHostname, 'mailhub.local');
    assert.equal(settingsPayload.settings.systemChecks.ptr.key, 'ptr');

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

test('auth pages preserve query messages instead of redirecting them away', async () => {
  const { child, baseUrl } = await startTestServer();

  try {
    for (const pathname of ['/login?error=hello', '/reset-password?token=abc123']) {
      const response = await fetch(`${baseUrl}${pathname}`, { redirect: 'manual' });

      assert.equal(response.status, 200);
      assert.equal(response.headers.get('location'), null);
      assert.match(await response.text(), /auth-root/);
    }
  } finally {
    child.kill('SIGTERM');
    await waitForExit(child, 1000);
  }
});

test('users can manage multiple smtp login credentials', async () => {
  const { child, baseUrl } = await startTestServer();

  try {
    const cookie = await login(baseUrl, 'admin', 'password123');
    const first = await createSmtpCredential(baseUrl, cookie, {
      username: 'admin-smtp-main',
      password: 'main-secret'
    });
    const second = await createSmtpCredential(baseUrl, cookie, {
      username: 'admin-smtp-app',
      password: 'app-secret'
    });

    assert.equal(first.username, 'admin-smtp-main');
    assert.equal(first.password, 'main-secret');
    assert.equal(second.username, 'admin-smtp-app');

    const list = await fetch(`${baseUrl}/api/smtp-credentials`, { headers: { Cookie: cookie } });
    assert.equal(list.status, 200);
    const listPayload = await list.json();
    assert.deepEqual(listPayload.credentials.map((credential) => credential.username), ['admin-smtp-app', 'admin-smtp-main']);
    assert.equal(listPayload.credentials[0].password, 'app-secret');

    const update = await fetch(`${baseUrl}/api/smtp-credentials/${second.id}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Cookie: cookie
      },
      body: JSON.stringify({ username: 'admin-smtp-app-renamed' })
    });
    assert.equal(update.status, 200);
    assert.equal((await update.json()).credential.password, 'app-secret');

    const deleted = await fetch(`${baseUrl}/api/smtp-credentials/${first.id}`, {
      method: 'DELETE',
      headers: { Cookie: cookie }
    });
    assert.equal(deleted.status, 200);
    assert.equal((await deleted.json()).deleted, true);
  } finally {
    child.kill('SIGTERM');
    await waitForExit(child, 1000);
  }
});

test('users can manage outbound smtp relays with recoverable passwords and send through a selected relay', async () => {
  const relayServer = await startFakeSmtpServer();
  const { child, baseUrl } = await startTestServer();

  try {
    const cookie = await login(baseUrl, 'admin', 'password123');
    const domainResponse = await fetch(`${baseUrl}/api/domains`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: cookie
      },
      body: JSON.stringify({
        domain: 'relay.example',
        selector: 'mh',
        senderHost: 'mail.relay.example',
        sendingIp: '127.0.0.1'
      })
    });
    assert.equal(domainResponse.status, 201);

    const createRelay = await fetch(`${baseUrl}/api/smtp-relays`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: cookie
      },
      body: JSON.stringify({
        name: 'Primary outbound',
        host: '127.0.0.1',
        port: relayServer.port,
        secure: false,
        username: 'relay-user',
        password: 'relay-password',
        helo: 'helo.relay.example',
        isDefault: true
      })
    });
    assert.equal(createRelay.status, 201);
    const created = await createRelay.json();
    assert.equal(created.relay.passwordSet, true);
    assert.equal('password' in created.relay, false);

    const list = await fetch(`${baseUrl}/api/smtp-relays`, { headers: { Cookie: cookie } });
    assert.equal(list.status, 200);
    const listed = await list.json();
    assert.equal(listed.relays.length, 1);
    assert.equal('password' in listed.relays[0], false);

    const detail = await fetch(`${baseUrl}/api/smtp-relays/${created.relay.id}`, { headers: { Cookie: cookie } });
    assert.equal(detail.status, 200);
    const detailBody = await detail.json();
    assert.equal(detailBody.relay.password, 'relay-password');
    assert.equal('passwordSecret' in detailBody.relay, false);

    const missingPatch = await fetch(`${baseUrl}/api/smtp-relays/999999`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Cookie: cookie
      },
      body: JSON.stringify({
        name: 'Missing relay',
        host: '127.0.0.1',
        port: relayServer.port,
        secure: false,
        username: 'missing-user',
        password: 'missing-password'
      })
    });
    assert.equal(missingPatch.status, 404);

    const updateWithoutPassword = await fetch(`${baseUrl}/api/smtp-relays/${created.relay.id}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Cookie: cookie
      },
      body: JSON.stringify({
        name: 'Primary outbound renamed',
        host: '127.0.0.1',
        port: relayServer.port,
        secure: false,
        username: 'relay-user'
      })
    });
    assert.equal(updateWithoutPassword.status, 200);
    assert.equal((await updateWithoutPassword.json()).relay.isDefault, true);
    const detailAfterPatch = await fetch(`${baseUrl}/api/smtp-relays/${created.relay.id}`, { headers: { Cookie: cookie } });
    assert.equal((await detailAfterPatch.json()).relay.password, 'relay-password');

    const invalidRelaySend = await fetch(`${baseUrl}/api/send`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: cookie
      },
      body: JSON.stringify({
        from: 'noreply@relay.example',
        to: 'user@example.com',
        subject: 'Invalid relay',
        text: 'hello',
        smtpRelayId: 999999
      })
    });
    assert.equal(invalidRelaySend.status, 400);

    const send = await fetch(`${baseUrl}/api/send`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: cookie
      },
      body: JSON.stringify({
        from: 'noreply@relay.example',
        to: 'user@example.com',
        subject: 'Relay send',
        text: 'hello',
        smtpRelayId: created.relay.id
      })
    });
    assert.equal(send.status, 202);
    assert.equal((await send.json()).smtpRelayId, created.relay.id);
    await waitForCondition(() => relayServer.messages.length === 1);
    const authCommand = relayServer.commands.find((command) => command.startsWith('AUTH PLAIN '));
    assert.ok(authCommand);
    assert.equal(Buffer.from(authCommand.replace('AUTH PLAIN ', ''), 'base64').toString('utf8'), '\0relay-user\0relay-password');

    const events = await fetch(`${baseUrl}/api/events`, { headers: { Cookie: cookie } });
    assert.equal(events.status, 200);
    const eventsBody = await events.json();
    assert.equal(eventsBody.events[0].smtpRelayId, created.relay.id);

    const eventDetail = await fetch(`${baseUrl}/api/events/${eventsBody.events[0].id}`, {
      headers: { Cookie: cookie }
    });
    assert.equal(eventDetail.status, 200);
    const eventDetailBody = await eventDetail.json();
    assert.equal(eventDetailBody.event.id, eventsBody.events[0].id);
    assert.equal(eventDetailBody.event.smtpRelayId, created.relay.id);
    assert.equal(Array.isArray(eventDetailBody.event.webhookDeliveries), true);
  } finally {
    child.kill('SIGTERM');
    await waitForExit(child, 1000);
    await relayServer.close();
  }
});

test('smtp relay selection prefers request relay then domain relay then user default relay', async () => {
  const requestRelayServer = await startFakeSmtpServer();
  const domainRelayServer = await startFakeSmtpServer();
  const defaultRelayServer = await startFakeSmtpServer();
  const { child, baseUrl } = await startTestServer();

  try {
    const cookie = await login(baseUrl, 'admin', 'password123');
    const defaultRelay = await createSmtpRelay(baseUrl, cookie, {
      name: 'Default relay',
      host: '127.0.0.1',
      port: defaultRelayServer.port,
      username: 'default-user',
      password: 'default-password',
      isDefault: true
    });
    const domainRelay = await createSmtpRelay(baseUrl, cookie, {
      name: 'Domain relay',
      host: '127.0.0.1',
      port: domainRelayServer.port,
      username: 'domain-user',
      password: 'domain-password'
    });
    const requestRelay = await createSmtpRelay(baseUrl, cookie, {
      name: 'Request relay',
      host: '127.0.0.1',
      port: requestRelayServer.port,
      username: 'request-user',
      password: 'request-password'
    });

    const domain = await createSendingDomain(baseUrl, cookie, {
      domain: 'relay-order.example',
      smtpRelayId: domainRelay.id
    });
    assert.equal(domain.smtpRelayId, domainRelay.id);

    const domainSend = await sendApiMail(baseUrl, cookie, {
      from: 'noreply@relay-order.example',
      to: 'domain@example.com',
      subject: 'Domain relay'
    });
    assert.equal(domainSend.smtpRelayId, domainRelay.id);
    await waitForCondition(() => domainRelayServer.messages.length === 1);
    assertRelayAuth(domainRelayServer, 'domain-user', 'domain-password');

    const requestSend = await sendApiMail(baseUrl, cookie, {
      from: 'noreply@relay-order.example',
      to: 'request@example.com',
      subject: 'Request relay',
      smtpRelayId: requestRelay.id
    });
    assert.equal(requestSend.smtpRelayId, requestRelay.id);
    await waitForCondition(() => requestRelayServer.messages.length === 1);
    assertRelayAuth(requestRelayServer, 'request-user', 'request-password');

    const testSend = await fetch(`${baseUrl}/api/domains/${domain.id}/test-send`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: cookie
      },
      body: JSON.stringify({
        to: 'test-send@example.com',
        subject: 'Selected relay test send',
        smtpRelayId: requestRelay.id
      })
    });
    assert.equal(testSend.status, 202);
    assert.equal((await testSend.json()).smtpRelayId, requestRelay.id);
    await waitForCondition(() => requestRelayServer.messages.length === 2);

    const invalidTestSend = await fetch(`${baseUrl}/api/domains/${domain.id}/test-send`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: cookie
      },
      body: JSON.stringify({
        to: 'invalid-test-send@example.com',
        smtpRelayId: 999999
      })
    });
    assert.equal(invalidTestSend.status, 400);

    const defaultDomain = await createSendingDomain(baseUrl, cookie, {
      domain: 'default-relay.example'
    });
    assert.equal(defaultDomain.smtpRelayId, null);
    const defaultSend = await sendApiMail(baseUrl, cookie, {
      from: 'noreply@default-relay.example',
      to: 'default@example.com',
      subject: 'Default relay'
    });
    assert.equal(defaultSend.smtpRelayId, defaultRelay.id);
    await waitForCondition(() => defaultRelayServer.messages.length === 1);
    assertRelayAuth(defaultRelayServer, 'default-user', 'default-password');
  } finally {
    child.kill('SIGTERM');
    await waitForExit(child, 1000);
    await requestRelayServer.close();
    await domainRelayServer.close();
    await defaultRelayServer.close();
  }
});

test('admin users can list audit logs', async () => {
  const { child, baseUrl } = await startTestServer();

  try {
    const cookie = await login(baseUrl, 'admin', 'password123');
    const response = await fetch(`${baseUrl}/api/admin/audit-logs`, {
      headers: { Cookie: cookie }
    });

    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { logs: [] });
  } finally {
    child.kill('SIGTERM');
    await waitForExit(child, 1000);
  }
});

test('admin users can list resource inventory', async () => {
  const { child, baseUrl, dataDir, sessionSecret } = await startTestServer();

  try {
    seedUsers(dataDir, sessionSecret, [{
      username: 'alice',
      email: 'alice@example.com',
      password: 'password123',
      status: 'active'
    }]);
    const adminCookie = await login(baseUrl, 'admin', 'password123');
    const userCookie = await login(baseUrl, 'alice', 'password123');

    const forbidden = await fetch(`${baseUrl}/api/admin/resources`, {
      headers: { Cookie: userCookie }
    });
    assert.equal(forbidden.status, 403);

    const response = await fetch(`${baseUrl}/api/admin/resources`, {
      headers: { Cookie: adminCookie }
    });
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.ok(Array.isArray(body.inventory.users));
    assert.ok(Array.isArray(body.inventory.warnings));
    assert.ok(body.inventory.users.some((entry) => entry.user.username === 'alice'));
  } finally {
    child.kill('SIGTERM');
    await waitForExit(child, 1000);
  }
});

test('admin users can transfer individual resources', async () => {
  const { child, baseUrl, dataDir, sessionSecret } = await startTestServer();

  try {
    const seeded = seedTransferResources(dataDir, sessionSecret);
    const adminCookie = await login(baseUrl, 'admin', 'password123');
    const aliceCookie = await login(baseUrl, 'alice', 'password123');

    const forbidden = await fetch(`${baseUrl}/api/admin/resources/domains/${seeded.domainId}/transfer`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: aliceCookie
      },
      body: JSON.stringify({ targetUserId: seeded.bobId })
    });
    assert.equal(forbidden.status, 403);

    const domain = await fetch(`${baseUrl}/api/admin/resources/domains/${seeded.domainId}/transfer`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: adminCookie
      },
      body: JSON.stringify({
        targetUserId: seeded.bobId,
        dnsCredentialMode: 'with_dns_credential'
      })
    });
    assert.equal(domain.status, 200);
    const domainBody = await domain.json();
    assert.equal(domainBody.domain.userId, seeded.bobId);
    assert.equal(domainBody.domain.dnsCredentialId, seeded.credentialId);

    const dns = await fetch(`${baseUrl}/api/admin/resources/dns-credentials/${seeded.standaloneCredentialId}/transfer`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: adminCookie
      },
      body: JSON.stringify({ targetUserId: seeded.bobId })
    });
    assert.equal(dns.status, 200);
    assert.equal((await dns.json()).credential.userId, seeded.bobId);

    const tokens = await fetch(`${baseUrl}/api/admin/resources/api-tokens/transfer`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: adminCookie
      },
      body: JSON.stringify({
        targetUserId: seeded.bobId,
        tokenIds: [seeded.apiTokenId]
      })
    });
    assert.equal(tokens.status, 200);
    const tokensBody = await tokens.json();
    assert.equal(tokensBody.tokens.length, 1);
    assert.equal(tokensBody.tokens[0].userId, seeded.bobId);

    const audit = await fetch(`${baseUrl}/api/admin/audit-logs?targetUserId=${seeded.bobId}`, {
      headers: { Cookie: adminCookie }
    });
    const actions = (await audit.json()).logs.map((entry) => entry.action);
    assert.ok(actions.includes('admin.transfer_domain'));
    assert.ok(actions.includes('admin.transfer_dns_credential'));
    assert.ok(actions.includes('admin.transfer_api_tokens'));
  } finally {
    child.kill('SIGTERM');
    await waitForExit(child, 1000);
  }
});

test('admin users can preview and execute user merge', async () => {
  const { child, baseUrl, dataDir, sessionSecret } = await startTestServer();

  try {
    const seeded = seedMergeResources(dataDir, sessionSecret);
    const adminCookie = await login(baseUrl, 'admin', 'password123');

    const previewResponse = await fetch(`${baseUrl}/api/admin/migrations/user-merge/preview`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: adminCookie
      },
      body: JSON.stringify({
        sourceUserId: seeded.sourceId,
        targetUserId: seeded.targetId
      })
    });
    assert.equal(previewResponse.status, 200);
    const preview = (await previewResponse.json()).preview;
    assert.equal(preview.confirmationText, 'MERGE mergesource INTO mergetarget');
    assert.equal(preview.counts.domains, 1);

    const invalid = await fetch(`${baseUrl}/api/admin/migrations/user-merge/execute`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: adminCookie
      },
      body: JSON.stringify({
        sourceUserId: seeded.sourceId,
        targetUserId: seeded.targetId,
        confirmation: 'wrong'
      })
    });
    assert.equal(invalid.status, 400);

    const execute = await fetch(`${baseUrl}/api/admin/migrations/user-merge/execute`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: adminCookie
      },
      body: JSON.stringify({
        sourceUserId: seeded.sourceId,
        targetUserId: seeded.targetId,
        confirmation: preview.confirmationText
      })
    });
    assert.equal(execute.status, 200);
    const result = (await execute.json()).result;
    assert.equal(result.counts.domains, 1);
    assert.equal(result.sourceUser.status, 'disabled');

    const audit = await fetch(`${baseUrl}/api/admin/audit-logs?action=admin.user_merge`, {
      headers: { Cookie: adminCookie }
    });
    assert.equal(audit.status, 200);
    assert.equal((await audit.json()).logs[0].targetUserId, seeded.targetId);
  } finally {
    child.kill('SIGTERM');
    await waitForExit(child, 1000);
  }
});

test('admin users can manage system email settings without exposing password', async () => {
  const { child, baseUrl, dataDir, sessionSecret } = await startTestServer();

  try {
    seedUsers(dataDir, sessionSecret, [{
      username: 'alice',
      email: 'alice@example.com',
      password: 'password123',
      status: 'active'
    }]);
    const adminCookie = await login(baseUrl, 'admin', 'password123');
    const userCookie = await login(baseUrl, 'alice', 'password123');

    const forbidden = await fetch(`${baseUrl}/api/admin/system-email`, {
      headers: { Cookie: userCookie }
    });
    assert.equal(forbidden.status, 403);

    const empty = await fetch(`${baseUrl}/api/admin/system-email`, {
      headers: { Cookie: adminCookie }
    });
    assert.equal(empty.status, 200);
    assert.equal((await empty.json()).settings.passwordSet, false);

    const saved = await fetch(`${baseUrl}/api/admin/system-email`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Cookie: adminCookie
      },
      body: JSON.stringify({
        host: 'smtp.example.com',
        port: 587,
        secure: false,
        username: 'mailer@example.com',
        password: 'smtp-password-123',
        helo: 'mail.example.com',
        fromEmail: 'notify@example.com',
        fromName: 'MailHub Notify',
        testRecipient: 'admin@example.com'
      })
    });
    assert.equal(saved.status, 200);
    const savedBody = await saved.json();
    assert.equal(savedBody.settings.host, 'smtp.example.com');
    assert.equal(savedBody.settings.port, 587);
    assert.equal(savedBody.settings.secure, false);
    assert.equal(savedBody.settings.passwordSet, true);
    assert.equal('password' in savedBody.settings, false);
    assert.equal(JSON.stringify(savedBody).includes('smtp-password-123'), false);

    const preserved = await fetch(`${baseUrl}/api/admin/system-email`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Cookie: adminCookie
      },
      body: JSON.stringify({
        host: 'smtp2.example.com',
        password: ''
      })
    });
    assert.equal(preserved.status, 200);
    const preservedBody = await preserved.json();
    assert.equal(preservedBody.settings.host, 'smtp2.example.com');
    assert.equal(preservedBody.settings.passwordSet, true);
    assert.equal(JSON.stringify(preservedBody).includes('smtp-password-123'), false);

    const audit = await fetch(`${baseUrl}/api/admin/audit-logs?action=admin.update_system_email`, {
      headers: { Cookie: adminCookie }
    });
    assert.equal(audit.status, 200);
    const [entry] = (await audit.json()).logs;
    assert.equal(entry.action, 'admin.update_system_email');
    assert.equal(entry.targetType, 'system_email');
    assert.equal(entry.summary.host, 'smtp2.example.com');
    assert.equal(entry.summary.password, undefined);
    assert.equal(entry.summary.passwordSet, true);
  } finally {
    child.kill('SIGTERM');
    await waitForExit(child, 1000);
  }
});

test('registration and verification resend use configured system email', async () => {
  const smtp = await startFakeSmtpServer();
  const { child, baseUrl, dataDir, sessionSecret } = await startTestServer();

  try {
    seedUsers(dataDir, sessionSecret, [
      { username: 'publicpending', email: 'publicpending@example.com', password: 'password123', status: 'pending_email' },
      { username: 'adminpending', email: 'adminpending@example.com', password: 'password123', status: 'pending_email' }
    ]);
    const adminCookie = await login(baseUrl, 'admin', 'password123');
    await saveSystemEmailSettings(baseUrl, adminCookie, smtp.port);

    const register = await fetch(`${baseUrl}/api/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'mailuser',
        email: 'mailuser@example.com',
        password: 'password123'
      })
    });
    assert.equal(register.status, 201);
    const registerBody = await register.json();
    assert.equal(registerBody.user.status, 'pending_email');
    assert.equal(registerBody.verificationEmailSent, true);
    assert.equal(countAccountTokensForUser(dataDir, sessionSecret, 'mailuser', 'email_verification'), 1);

    const publicResend = await fetch(`${baseUrl}/api/auth/resend-verification`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'publicpending@example.com' })
    });
    assert.equal(publicResend.status, 202);
    const publicResendBody = await publicResend.json();
    assert.equal(publicResendBody.message, '如果账号需要验证，我们会发送验证邮件。');
    assert.equal('verificationEmailSent' in publicResendBody, false);
    assert.equal('result' in publicResendBody, false);
    await waitForCondition(() => countAccountTokensForUser(dataDir, sessionSecret, 'publicpending', 'email_verification') === 1);

    const usersResponse = await fetch(`${baseUrl}/api/admin/users`, {
      headers: { Cookie: adminCookie }
    });
    const adminPending = (await usersResponse.json()).users.find((user) => user.username === 'adminpending');
    assert.ok(adminPending);
    const adminResend = await fetch(`${baseUrl}/api/admin/users/${adminPending.id}/resend-verification`, {
      method: 'POST',
      headers: { Cookie: adminCookie }
    });
    assert.equal(adminResend.status, 202);
    assert.equal((await adminResend.json()).verificationEmailSent, true);
    assert.equal(countAccountTokensForUser(dataDir, sessionSecret, 'adminpending', 'email_verification'), 1);

    assert.ok(smtp.commands.some((command) => command === 'MAIL FROM:<notify@example.com>'));
    assert.ok(smtp.commands.some((command) => command === 'RCPT TO:<mailuser@example.com>'));
    assert.ok(smtp.commands.some((command) => command === 'RCPT TO:<publicpending@example.com>'));
    assert.ok(smtp.commands.some((command) => command === 'RCPT TO:<adminpending@example.com>'));
    assert.equal(JSON.stringify(smtp.commands).includes('smtp-password-123'), false);
  } finally {
    child.kill('SIGTERM');
    await waitForExit(child, 1000);
    await smtp.close();
  }
});

test('public verification resend is generic and does not create tokens without mail config', async () => {
  const { child, baseUrl, dataDir, sessionSecret } = await startTestServer();

  try {
    seedUsers(dataDir, sessionSecret, [{
      username: 'pendingnomail',
      email: 'pendingnomail@example.com',
      password: 'password123',
      status: 'pending_email'
    }]);

    const response = await fetch(`${baseUrl}/api/auth/resend-verification`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'pendingnomail@example.com' })
    });

    assert.equal(response.status, 202);
    assert.deepEqual(await response.json(), {
      message: '如果账号需要验证，我们会发送验证邮件。'
    });
    assert.equal(countAccountTokensForUser(dataDir, sessionSecret, 'pendingnomail', 'email_verification'), 0);
  } finally {
    child.kill('SIGTERM');
    await waitForExit(child, 1000);
  }
});

test('registration reports pending email when system email is not configured', async () => {
  const { child, baseUrl, dataDir, sessionSecret } = await startTestServer();

  try {
    const register = await fetch(`${baseUrl}/api/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'nomailuser',
        email: 'nomailuser@example.com',
        password: 'password123'
      })
    });

    assert.equal(register.status, 201);
    const body = await register.json();
    assert.equal(body.user.status, 'pending_email');
    assert.equal(body.verificationEmailSent, false);
    assert.match(body.message, /验证邮件暂未发送/);
    assert.equal(countAccountTokensForUser(dataDir, sessionSecret, 'nomailuser', 'email_verification'), 1);
  } finally {
    child.kill('SIGTERM');
    await waitForExit(child, 1000);
  }
});

test('admin users can send system email test messages', async () => {
  const smtp = await startFakeSmtpServer();
  const { child, baseUrl } = await startTestServer();

  try {
    const adminCookie = await login(baseUrl, 'admin', 'password123');
    await saveSystemEmailSettings(baseUrl, adminCookie, smtp.port);

    const response = await fetch(`${baseUrl}/api/admin/system-email/test`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: adminCookie
      },
      body: JSON.stringify({ to: 'operator@example.com' })
    });

    assert.equal(response.status, 202);
    const body = await response.json();
    assert.equal(body.result.ok, true);
    assert.equal(body.result.queueId, 'SYS123');
    assert.equal(JSON.stringify(body).includes('smtp-password-123'), false);
    assert.ok(smtp.commands.some((command) => command === 'RCPT TO:<operator@example.com>'));

    const audit = await fetch(`${baseUrl}/api/admin/audit-logs?action=admin.test_system_email`, {
      headers: { Cookie: adminCookie }
    });
    assert.equal(audit.status, 200);
    const [entry] = (await audit.json()).logs;
    assert.equal(entry.targetType, 'system_email');
    assert.equal(entry.summary.to, 'operator@example.com');
    assert.equal(entry.summary.ok, true);
  } finally {
    child.kill('SIGTERM');
    await waitForExit(child, 1000);
    await smtp.close();
  }
});

test('public forgot password is generic and sends reset email when configured', async () => {
  const smtp = await startFakeSmtpServer({ responseDelayMs: 700 });
  const { child, baseUrl, dataDir, sessionSecret } = await startTestServer();

  try {
    seedUsers(dataDir, sessionSecret, [{
      username: 'resetme',
      email: 'resetme@example.com',
      password: 'password123',
      status: 'active'
    }]);
    const adminCookie = await login(baseUrl, 'admin', 'password123');
    await saveSystemEmailSettings(baseUrl, adminCookie, smtp.port);

    const startedAt = Date.now();
    const existing = await fetch(`${baseUrl}/api/auth/forgot-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'resetme@example.com' })
    });
    const elapsedMs = Date.now() - startedAt;
    assert.equal(existing.status, 202);
    assert.equal(elapsedMs < 500, true);
    assert.deepEqual(await existing.json(), {
      message: '如果邮箱存在，我们会发送密码重置邮件。'
    });
    await waitForCondition(() => countAccountTokensForUser(dataDir, sessionSecret, 'resetme', 'password_reset') === 1);

    const missing = await fetch(`${baseUrl}/api/auth/forgot-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'missing@example.com' })
    });
    assert.equal(missing.status, 202);
    assert.deepEqual(await missing.json(), {
      message: '如果邮箱存在，我们会发送密码重置邮件。'
    });

    await waitForCondition(() => smtp.commands.some((command) => command === 'RCPT TO:<resetme@example.com>'));
  } finally {
    child.kill('SIGTERM');
    await waitForExit(child, 1000);
    await smtp.close();
  }
});

test('public reset password consumes token and updates password', async () => {
  const { child, baseUrl, dataDir, sessionSecret } = await startTestServer();

  try {
    seedUsers(dataDir, sessionSecret, [{
      username: 'tokenreset',
      email: 'tokenreset@example.com',
      password: 'password123',
      status: 'active'
    }]);
    const token = createPasswordResetToken(dataDir, sessionSecret, 'tokenreset');

    const response = await fetch(`${baseUrl}/api/auth/reset-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token,
        password: 'new-password-123'
      })
    });
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), {
      message: '密码已重置，请使用新密码登录。'
    });

    const oldLogin = await loginResponse(baseUrl, 'tokenreset', 'password123');
    assert.equal(oldLogin.status, 401);
    const newLogin = await loginResponse(baseUrl, 'tokenreset', 'new-password-123');
    assert.equal(newLogin.status, 200);

    const reused = await fetch(`${baseUrl}/api/auth/reset-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token,
        password: 'another-password-123'
      })
    });
    assert.equal(reused.status, 400);
  } finally {
    child.kill('SIGTERM');
    await waitForExit(child, 1000);
  }
});

test('admin users can trigger password reset email and set temporary password', async () => {
  const smtp = await startFakeSmtpServer();
  const { child, baseUrl, dataDir, sessionSecret } = await startTestServer();

  try {
    seedUsers(dataDir, sessionSecret, [
      { username: 'targetuser', email: 'targetuser@example.com', password: 'password123', status: 'active' },
      { username: 'member2', email: 'member2@example.com', password: 'password123', status: 'active' }
    ]);
    const adminCookie = await login(baseUrl, 'admin', 'password123');
    const memberCookie = await login(baseUrl, 'member2', 'password123');
    await saveSystemEmailSettings(baseUrl, adminCookie, smtp.port);

    const usersResponse = await fetch(`${baseUrl}/api/admin/users`, {
      headers: { Cookie: adminCookie }
    });
    const target = (await usersResponse.json()).users.find((user) => user.username === 'targetuser');
    assert.ok(target);

    const forbiddenReset = await fetch(`${baseUrl}/api/admin/users/${target.id}/password-reset`, {
      method: 'POST',
      headers: { Cookie: memberCookie }
    });
    assert.equal(forbiddenReset.status, 403);

    const reset = await fetch(`${baseUrl}/api/admin/users/${target.id}/password-reset`, {
      method: 'POST',
      headers: { Cookie: adminCookie }
    });
    assert.equal(reset.status, 202);
    assert.equal((await reset.json()).result.ok, true);
    assert.equal(countAccountTokensForUser(dataDir, sessionSecret, 'targetuser', 'password_reset'), 1);
    assert.ok(smtp.commands.some((command) => command === 'RCPT TO:<targetuser@example.com>'));

    const forbiddenTemporary = await fetch(`${baseUrl}/api/admin/users/${target.id}/temporary-password`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: memberCookie
      },
      body: JSON.stringify({ password: 'temporary-123' })
    });
    assert.equal(forbiddenTemporary.status, 403);

    const temporary = await fetch(`${baseUrl}/api/admin/users/${target.id}/temporary-password`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: adminCookie
      },
      body: JSON.stringify({ password: 'temporary-123' })
    });
    assert.equal(temporary.status, 200);
    assert.equal((await temporary.json()).user.id, target.id);
    assert.equal(countUnusedAccountTokensForUser(dataDir, sessionSecret, 'targetuser', 'password_reset'), 0);

    const oldLogin = await loginResponse(baseUrl, 'targetuser', 'password123');
    assert.equal(oldLogin.status, 401);
    const tempLogin = await loginResponse(baseUrl, 'targetuser', 'temporary-123');
    assert.equal(tempLogin.status, 200);

    const audit = await fetch(`${baseUrl}/api/admin/audit-logs?targetUserId=${target.id}`, {
      headers: { Cookie: adminCookie }
    });
    assert.equal(audit.status, 200);
    const logs = (await audit.json()).logs;
    assert.ok(logs.some((entry) => entry.action === 'admin.password_reset'));
    const temporaryLog = logs.find((entry) => entry.action === 'admin.temporary_password');
    assert.ok(temporaryLog);
    assert.equal(temporaryLog.summary.username, 'targetuser');
    assert.equal(temporaryLog.summary.password, undefined);
    assert.equal(JSON.stringify(temporaryLog).includes('temporary-123'), false);
  } finally {
    child.kill('SIGTERM');
    await waitForExit(child, 1000);
    await smtp.close();
  }
});

test('non-admin users cannot list audit logs', async () => {
  const { child, baseUrl, dataDir, sessionSecret } = await startTestServer();

  try {
    seedUsers(dataDir, sessionSecret, [{
      username: 'alice',
      email: 'alice@example.com',
      password: 'password123',
      status: 'active'
    }]);
    const cookie = await login(baseUrl, 'alice', 'password123');

    const response = await fetch(`${baseUrl}/api/admin/audit-logs`, {
      headers: { Cookie: cookie }
    });

    assert.equal(response.status, 403);
  } finally {
    child.kill('SIGTERM');
    await waitForExit(child, 1000);
  }
});

test('admin user patch rejects invalid status with a bad request', async () => {
  const { child, baseUrl, dataDir, sessionSecret } = await startTestServer();

  try {
    seedUsers(dataDir, sessionSecret, [{
      username: 'badstatus',
      email: 'badstatus@example.com',
      password: 'password123',
      status: 'active'
    }]);
    const cookie = await login(baseUrl, 'admin', 'password123');
    const usersResponse = await fetch(`${baseUrl}/api/admin/users`, {
      headers: { Cookie: cookie }
    });
    assert.equal(usersResponse.status, 200);
    const usersBody = await usersResponse.json();
    const target = usersBody.users.find((user) => user.username === 'badstatus');
    assert.ok(target);

    const response = await fetch(`${baseUrl}/api/admin/users/${target.id}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Cookie: cookie
      },
      body: JSON.stringify({ status: 'archived' })
    });

    assert.equal(response.status, 400);
    assert.equal((await response.json()).error, '用户状态不正确。');

    const shortPassword = await fetch(`${baseUrl}/api/admin/users/${target.id}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Cookie: cookie
      },
      body: JSON.stringify({ password: 'short' })
    });
    assert.equal(shortPassword.status, 400);
    assert.equal((await shortPassword.json()).error, '密码至少需要 8 位。');
  } finally {
    child.kill('SIGTERM');
    await waitForExit(child, 1000);
  }
});

test('self registration creates a pending email user and verification token without a session', async () => {
  const { child, baseUrl, dataDir, sessionSecret } = await startTestServer();

  try {
    const register = await fetch(`${baseUrl}/api/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'newuser',
        email: 'newuser@example.com',
        password: 'password123'
      })
    });

    assert.equal(register.status, 201);
    assert.equal(sessionCookieFrom(register), '');
    const text = await register.text();
    assert.doesNotMatch(text, /token/i);
    const body = JSON.parse(text);
    assert.equal('token' in body, false);
    assert.equal('token' in body.user, false);
    assert.equal('tokenHash' in body.user, false);
    assert.equal(body.user.status, 'pending_email');
    assert.match(body.message, /验证邮箱/);
    assert.equal(countAccountTokensForUser(dataDir, sessionSecret, 'newuser', 'email_verification'), 1);

    const login = await loginResponse(baseUrl, 'newuser', 'password123');
    assert.equal(login.status, 403);
    assert.equal(sessionCookieFrom(login), '');
    assert.equal((await login.json()).error, '请先验证邮箱。');
  } finally {
    child.kill('SIGTERM');
    await waitForExit(child, 1000);
  }
});

test('email verification route consumes token and moves user to admin review', async () => {
  const { child, baseUrl, dataDir, sessionSecret } = await startTestServer();

  try {
    const created = createPendingEmailUserWithVerificationToken(dataDir, sessionSecret, {
      username: 'verifyme',
      email: 'verifyme@example.com',
      password: 'password123',
      status: 'pending_email'
    });

    const missing = await fetch(`${baseUrl}/api/auth/verify-email`);
    assert.equal(missing.status, 400);
    assert.equal(sessionCookieFrom(missing), '');

    const invalid = await fetch(`${baseUrl}/api/auth/verify-email?token=not-a-real-token`);
    assert.equal(invalid.status, 400);
    assert.equal(sessionCookieFrom(invalid), '');

    const response = await fetch(`${baseUrl}/api/auth/verify-email?token=${encodeURIComponent(created.token)}`);
    assert.equal(response.status, 200);
    assert.equal(sessionCookieFrom(response), '');
    const body = await response.json();
    assert.equal(body.user.id, created.user.id);
    assert.equal(body.user.status, 'pending_review');
    assert.match(body.message, /管理员审核/);

    const reused = await fetch(`${baseUrl}/api/auth/verify-email?token=${encodeURIComponent(created.token)}`);
    assert.equal(reused.status, 400);
    assert.equal(sessionCookieFrom(reused), '');

    const login = await loginResponse(baseUrl, 'verifyme', 'password123');
    assert.equal(login.status, 403);
    assert.equal(sessionCookieFrom(login), '');
    assert.equal((await login.json()).error, '账号正在等待管理员审核。');
  } finally {
    child.kill('SIGTERM');
    await waitForExit(child, 1000);
  }
});

test('admin users can approve pending review users with an audit log', async () => {
  const { child, baseUrl, dataDir, sessionSecret } = await startTestServer();

  try {
    seedUsers(dataDir, sessionSecret, [
      { username: 'reviewme', email: 'reviewme@example.com', password: 'password123', status: 'pending_review' },
      { username: 'emailonly', email: 'emailonly@example.com', password: 'password123', status: 'pending_email' },
      { username: 'disabledreview', email: 'disabledreview@example.com', password: 'password123', status: 'disabled' },
      { username: 'member', email: 'member@example.com', password: 'password123', status: 'active' }
    ]);

    const adminCookie = await login(baseUrl, 'admin', 'password123');
    const usersResponse = await fetch(`${baseUrl}/api/admin/users`, {
      headers: { Cookie: adminCookie }
    });
    assert.equal(usersResponse.status, 200);
    const users = (await usersResponse.json()).users;
    const target = users.find((user) => user.username === 'reviewme');
    const pendingEmail = users.find((user) => user.username === 'emailonly');
    const disabled = users.find((user) => user.username === 'disabledreview');
    assert.ok(target);
    assert.ok(pendingEmail);
    assert.ok(disabled);

    const memberCookie = await login(baseUrl, 'member', 'password123');
    const nonAdmin = await fetch(`${baseUrl}/api/admin/users/${target.id}/approve`, {
      method: 'POST',
      headers: { Cookie: memberCookie }
    });
    assert.equal(nonAdmin.status, 403);

    const missing = await fetch(`${baseUrl}/api/admin/users/999999/approve`, {
      method: 'POST',
      headers: { Cookie: adminCookie }
    });
    assert.equal(missing.status, 404);

    const pendingEmailResponse = await fetch(`${baseUrl}/api/admin/users/${pendingEmail.id}/approve`, {
      method: 'POST',
      headers: { Cookie: adminCookie }
    });
    assert.equal(pendingEmailResponse.status, 400);
    assert.match((await pendingEmailResponse.json()).error, /验证邮箱|等待审核/);

    const disabledResponse = await fetch(`${baseUrl}/api/admin/users/${disabled.id}/approve`, {
      method: 'POST',
      headers: { Cookie: adminCookie }
    });
    assert.equal(disabledResponse.status, 400);
    assert.match((await disabledResponse.json()).error, /等待审核|只能审批/);

    const response = await fetch(`${baseUrl}/api/admin/users/${target.id}/approve`, {
      method: 'POST',
      headers: { Cookie: adminCookie }
    });
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.user.id, target.id);
    assert.equal(body.user.status, 'active');

    const approvedCookie = await login(baseUrl, 'reviewme', 'password123');
    assert.ok(approvedCookie);

    const auditResponse = await fetch(`${baseUrl}/api/admin/audit-logs?action=admin.approve_user`, {
      headers: { Cookie: adminCookie }
    });
    assert.equal(auditResponse.status, 200);
    const [entry] = (await auditResponse.json()).logs;
    assert.equal(entry.action, 'admin.approve_user');
    assert.equal(entry.targetType, 'user');
    assert.equal(entry.targetId, String(target.id));
    assert.equal(entry.targetUserId, target.id);
    assert.equal(entry.summary.username, 'reviewme');
    assert.equal(entry.summary.status, 'active');
    assert.equal(entry.summary.password, undefined);
    assert.equal(entry.summary.token, undefined);
  } finally {
    child.kill('SIGTERM');
    await waitForExit(child, 1000);
  }
});

test('login returns account status restrictions only after password verification', async () => {
  const { child, baseUrl, dataDir, sessionSecret } = await startTestServer();

  try {
    seedUsers(dataDir, sessionSecret, [
      { username: 'pendingemail', email: 'pendingemail@example.com', password: 'password123', status: 'pending_email' },
      { username: 'pendingreview', email: 'pendingreview@example.com', password: 'password123', status: 'pending_review' },
      { username: 'disableduser', email: 'disableduser@example.com', password: 'password123', status: 'disabled' },
      { username: 'activeuser', email: 'activeuser@example.com', password: 'password123', status: 'active' }
    ]);

    await assertLoginDeniedByStatus(baseUrl, 'pendingemail', '请先验证邮箱。');
    await assertLoginDeniedByStatus(baseUrl, 'pendingreview', '账号正在等待管理员审核。');
    await assertLoginDeniedByStatus(baseUrl, 'disableduser', '账号已被禁用。');

    const active = await loginResponse(baseUrl, 'activeuser', 'password123');
    assert.equal(active.status, 200);
    assert.ok(sessionCookieFrom(active));
  } finally {
    child.kill('SIGTERM');
    await waitForExit(child, 1000);
  }
});

test('admin audit log actor filter rejects non-decimal user ids', async () => {
  const { child, baseUrl, dataDir, sessionSecret } = await startTestServer();

  try {
    seedAuditLogs(dataDir, sessionSecret);
    const cookie = await login(baseUrl, 'admin', 'password123');

    assert.deepEqual(
      await auditLogActions(baseUrl, cookie, 'actorUserId=1'),
      ['audit.actor-one']
    );
    assert.deepEqual(
      await auditLogActions(baseUrl, cookie, 'actorUserId=1e2'),
      ['audit.actor-one-hundred', 'audit.actor-one']
    );
  } finally {
    child.kill('SIGTERM');
    await waitForExit(child, 1000);
  }
});

test('admin audit log date filter ignores invalid dates', async () => {
  const { child, baseUrl, dataDir, sessionSecret } = await startTestServer();

  try {
    seedAuditLogs(dataDir, sessionSecret);
    const cookie = await login(baseUrl, 'admin', 'password123');

    assert.deepEqual(await auditLogActions(baseUrl, cookie, 'from=2999-01-01T00%3A00%3A00.000Z'), []);
    assert.deepEqual(
      await auditLogActions(baseUrl, cookie, 'from=2026-02-31'),
      ['audit.actor-one-hundred', 'audit.actor-one']
    );
  } finally {
    child.kill('SIGTERM');
    await waitForExit(child, 1000);
  }
});

async function startTestServer() {
  const port = await freePort();
  const dataDir = mkdtempSync(path.join(tmpdir(), 'mailhub-server-test-'));
  const sessionSecret = 'test-session-secret';
  const child = spawn(process.execPath, ['src/server.js'], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      PORT: String(port),
      DATA_DIR: dataDir,
      ADMIN_PASSWORD: 'password123',
      SESSION_SECRET: sessionSecret,
      DNS_AUTO_CHECK_ENABLED: 'false',
      SUBMISSION_ENABLED: 'false'
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  await waitForOutput(child, 'MailHub listening');
  return { child, baseUrl: `http://127.0.0.1:${port}`, dataDir, sessionSecret };
}

async function login(baseUrl, username, password) {
  const response = await loginResponse(baseUrl, username, password);
  assert.equal(response.status, 200);
  const cookie = sessionCookieFrom(response);
  assert.ok(cookie);
  return cookie;
}

function loginResponse(baseUrl, username, password) {
  return fetch(`${baseUrl}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
}

async function assertLoginDeniedByStatus(baseUrl, username, message) {
  const wrongPassword = await loginResponse(baseUrl, username, 'wrong-password');
  assert.equal(wrongPassword.status, 401);
  assert.equal((await wrongPassword.json()).error, '账号或密码不正确。');
  assert.equal(sessionCookieFrom(wrongPassword), '');

  const correctPassword = await loginResponse(baseUrl, username, 'password123');
  assert.equal(correctPassword.status, 403);
  assert.equal((await correctPassword.json()).error, message);
  assert.equal(sessionCookieFrom(correctPassword), '');
}

function sessionCookieFrom(response) {
  return response.headers.get('set-cookie')?.split(';')[0] || '';
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

function seedTransferResources(dataDir, sessionSecret) {
  const script = `
    import {
      initDatabase,
      createApiToken,
      createDomain,
      createUser,
      saveDnsCredential
    } from './src/db.js';

    initDatabase(process.env.DATA_DIR, process.env.SESSION_SECRET);
    const alice = createUser({ username: 'alice', email: 'alice@example.com', password: 'password123', status: 'active' });
    const bob = createUser({ username: 'bob', email: 'bob@example.com', password: 'password123', status: 'active' });
    const credential = saveDnsCredential(alice.id, {
      name: 'Alice DNS',
      provider: 'cloudflare',
      zoneName: 'alice.example',
      credentials: { apiToken: 'secret-token' }
    });
    const standaloneCredential = saveDnsCredential(alice.id, {
      name: 'Standalone DNS',
      provider: 'cloudflare',
      zoneName: 'standalone.example',
      credentials: { apiToken: 'standalone-secret-token' }
    });
    const domain = createDomain(alice.id, {
      dnsCredentialId: credential.id,
      domain: 'alice.example',
      selector: 'mh202607',
      verificationToken: 'token',
      dkimPublic: 'public',
      dkimPrivate: 'private',
      senderHost: 'mail.alice.example',
      sendingIp: '127.0.0.1',
      spfExtra: '',
      dmarcPolicy: 'none',
      dmarcRua: ''
    });
    const apiToken = createApiToken(alice.id, 'primary');
    console.log(JSON.stringify({
      aliceId: alice.id,
      bobId: bob.id,
      domainId: domain.id,
      credentialId: credential.id,
      standaloneCredentialId: standaloneCredential.id,
      apiTokenId: apiToken.id
    }));
  `;
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      DATA_DIR: dataDir,
      SESSION_SECRET: sessionSecret
    },
    encoding: 'utf8'
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return JSON.parse(result.stdout);
}

function seedMergeResources(dataDir, sessionSecret) {
  const script = `
    import {
      initDatabase,
      createApiToken,
      createDomain,
      createUser,
      logSendEvent,
      saveDnsCredential
    } from './src/db.js';

    initDatabase(process.env.DATA_DIR, process.env.SESSION_SECRET);
    const source = createUser({ username: 'mergesource', email: 'mergesource@example.com', password: 'password123', status: 'active' });
    const target = createUser({ username: 'mergetarget', email: 'mergetarget@example.com', password: 'password123', status: 'active' });
    const credential = saveDnsCredential(source.id, {
      name: 'Merge DNS',
      provider: 'cloudflare',
      zoneName: 'merge.example',
      credentials: { apiToken: 'merge-secret-token' }
    });
    const domain = createDomain(source.id, {
      dnsCredentialId: credential.id,
      domain: 'merge.example',
      selector: 'mh202607',
      verificationToken: 'token',
      dkimPublic: 'public',
      dkimPrivate: 'private',
      senderHost: 'mail.merge.example',
      sendingIp: '127.0.0.1',
      spfExtra: '',
      dmarcPolicy: 'none',
      dmarcRua: ''
    });
    createApiToken(source.id, 'primary');
    logSendEvent({
      userId: source.id,
      domainId: domain.id,
      sender: 'noreply@merge.example',
      recipients: ['a@example.com'],
      subject: 'Queued',
      status: 'queued'
    });
    console.log(JSON.stringify({ sourceId: source.id, targetId: target.id }));
  `;
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      DATA_DIR: dataDir,
      SESSION_SECRET: sessionSecret
    },
    encoding: 'utf8'
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return JSON.parse(result.stdout);
}

function createPendingEmailUserWithVerificationToken(dataDir, sessionSecret, user) {
  const script = `
    import { initDatabase, createUser, createAccountToken } from './src/db.js';

    initDatabase(process.env.DATA_DIR, process.env.SESSION_SECRET);
    const user = createUser(JSON.parse(process.env.SEED_USER));
    const token = createAccountToken(user.id, 'email_verification', { ttlMinutes: 24 * 60 });
    console.log(JSON.stringify({ user, token: token.token }));
  `;
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      DATA_DIR: dataDir,
      SESSION_SECRET: sessionSecret,
      SEED_USER: JSON.stringify(user)
    },
    encoding: 'utf8'
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return JSON.parse(result.stdout);
}

function createPasswordResetToken(dataDir, sessionSecret, username) {
  const script = `
    import { initDatabase, getUserByLogin, createAccountToken } from './src/db.js';

    initDatabase(process.env.DATA_DIR, process.env.SESSION_SECRET);
    const user = getUserByLogin(process.env.TOKEN_USERNAME);
    const token = createAccountToken(user.id, 'password_reset', { ttlMinutes: 60 });
    console.log(token.token);
  `;
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      DATA_DIR: dataDir,
      SESSION_SECRET: sessionSecret,
      TOKEN_USERNAME: username
    },
    encoding: 'utf8'
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return result.stdout.trim();
}

function countAccountTokensForUser(dataDir, sessionSecret, username, purpose) {
  return countAccountTokens(dataDir, sessionSecret, username, purpose, false);
}

function countUnusedAccountTokensForUser(dataDir, sessionSecret, username, purpose) {
  return countAccountTokens(dataDir, sessionSecret, username, purpose, true);
}

function countAccountTokens(dataDir, sessionSecret, username, purpose, unusedOnly) {
  const script = `
    import path from 'node:path';
    import { DatabaseSync } from 'node:sqlite';
    import { initDatabase, getUserByLogin } from './src/db.js';

    initDatabase(process.env.DATA_DIR, process.env.SESSION_SECRET);
    const user = getUserByLogin(process.env.TOKEN_USERNAME);
    const database = new DatabaseSync(path.join(process.env.DATA_DIR, 'mailhub.sqlite'));
    database.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');
    const unusedFilter = process.env.TOKEN_UNUSED_ONLY === 'true' ? ' AND used_at IS NULL' : '';
    const row = user
      ? database
          .prepare('SELECT COUNT(*) AS count FROM account_tokens WHERE user_id = ? AND purpose = ?' + unusedFilter)
          .get(user.id, process.env.TOKEN_PURPOSE)
      : { count: 0 };
    console.log(String(row.count));
  `;
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      DATA_DIR: dataDir,
      SESSION_SECRET: sessionSecret,
      TOKEN_USERNAME: username,
      TOKEN_PURPOSE: purpose,
      TOKEN_UNUSED_ONLY: String(unusedOnly)
    },
    encoding: 'utf8'
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return Number(result.stdout.trim());
}

function seedAuditLogs(dataDir, sessionSecret) {
  const script = `
    import path from 'node:path';
    import { DatabaseSync } from 'node:sqlite';
    import { initDatabase, logAudit } from './src/db.js';

    initDatabase(process.env.DATA_DIR, process.env.SESSION_SECRET);
    const actorOneId = logAudit({
      actorUserId: 1,
      action: 'audit.actor-one',
      targetType: 'system',
      summary: { label: 'actor-one' }
    });
    const actorOneHundredId = logAudit({
      actorUserId: 100,
      action: 'audit.actor-one-hundred',
      targetType: 'system',
      summary: { label: 'actor-one-hundred' }
    });
    const db = new DatabaseSync(path.join(process.env.DATA_DIR, 'mailhub.sqlite'));
    db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');
    const update = db.prepare('UPDATE audit_logs SET created_at = ? WHERE id = ?');
    update.run('2026-02-01T00:00:00.000Z', actorOneId);
    update.run('2026-02-02T00:00:00.000Z', actorOneHundredId);
  `;
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      DATA_DIR: dataDir,
      SESSION_SECRET: sessionSecret
    },
    encoding: 'utf8'
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
}

async function auditLogActions(baseUrl, cookie, query) {
  const response = await fetch(`${baseUrl}/api/admin/audit-logs?${query}`, {
    headers: { Cookie: cookie }
  });
  assert.equal(response.status, 200);
  const body = await response.json();
  return body.logs.map((log) => log.action);
}

async function saveSystemEmailSettings(baseUrl, cookie, smtpPort) {
  const response = await fetch(`${baseUrl}/api/admin/system-email`, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      Cookie: cookie
    },
    body: JSON.stringify({
      host: '127.0.0.1',
      port: smtpPort,
      secure: false,
      username: 'mailer@example.com',
      password: 'smtp-password-123',
      helo: 'mail.example.com',
      fromEmail: 'notify@example.com',
      fromName: 'MailHub Notify',
      testRecipient: 'admin@example.com'
    })
  });
  assert.equal(response.status, 200);
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
      sendingIp: data.sendingIp || '127.0.0.1',
      smtpRelayId: data.smtpRelayId
    })
  });
  assert.equal(response.status, 201);
  return (await response.json()).domain;
}

async function createSmtpRelay(baseUrl, cookie, data = {}) {
  const response = await fetch(`${baseUrl}/api/smtp-relays`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Cookie: cookie
    },
    body: JSON.stringify({
      name: data.name || 'Relay',
      host: data.host || '127.0.0.1',
      port: data.port,
      secure: data.secure || false,
      username: data.username || '',
      password: data.password || '',
      helo: data.helo || '',
      isDefault: data.isDefault || false
    })
  });
  assert.equal(response.status, 201);
  return (await response.json()).relay;
}

async function createSmtpCredential(baseUrl, cookie, data = {}) {
  const response = await fetch(`${baseUrl}/api/smtp-credentials`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Cookie: cookie
    },
    body: JSON.stringify(data)
  });
  assert.equal(response.status, 201);
  return (await response.json()).credential;
}

async function sendApiMail(baseUrl, cookie, data) {
  const response = await fetch(`${baseUrl}/api/send`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Cookie: cookie
    },
    body: JSON.stringify({
      from: data.from,
      to: data.to,
      subject: data.subject,
      text: data.text || 'hello',
      smtpRelayId: data.smtpRelayId
    })
  });
  assert.equal(response.status, 202);
  return response.json();
}

function assertRelayAuth(relayServer, username, password) {
  const authCommand = relayServer.commands.find((command) => command.startsWith('AUTH PLAIN '));
  assert.ok(authCommand);
  assert.equal(Buffer.from(authCommand.replace('AUTH PLAIN ', ''), 'base64').toString('utf8'), `\0${username}\0${password}`);
}

function startFakeSmtpServer({ responseDelayMs = 0 } = {}) {
  const commands = [];
  const messages = [];
  const server = net.createServer((socket) => {
    socket.setEncoding('utf8');
    writeSmtpResponse(socket, '220 relay.test ESMTP ready', responseDelayMs);
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
            writeSmtpResponse(socket, '250 2.0.0 queued as SYS123', responseDelayMs);
          } else {
            messageLines.push(line);
          }
          continue;
        }

        commands.push(line);
        if (line.startsWith('EHLO')) {
          writeSmtpResponse(socket, '250-relay.test\r\n250 AUTH PLAIN', responseDelayMs);
        } else if (line.startsWith('AUTH PLAIN')) {
          writeSmtpResponse(socket, '235 2.7.0 authentication successful', responseDelayMs);
        } else if (line.startsWith('MAIL FROM')) {
          writeSmtpResponse(socket, '250 2.1.0 sender ok', responseDelayMs);
        } else if (line.startsWith('RCPT TO')) {
          writeSmtpResponse(socket, '250 2.1.5 recipient ok', responseDelayMs);
        } else if (line === 'DATA') {
          dataMode = true;
          writeSmtpResponse(socket, '354 end with dot', responseDelayMs);
        } else if (line === 'QUIT') {
          writeSmtpResponse(socket, '221 bye', responseDelayMs);
          socket.end();
        }
      }
    });
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve({
        port: server.address().port,
        commands,
        messages,
        close: () => new Promise((closeResolve) => server.close(closeResolve))
      });
    });
  });
}

function writeSmtpResponse(socket, response, delayMs) {
  const write = () => socket.write(`${response}\r\n`);
  if (delayMs > 0) setTimeout(write, delayMs);
  else write();
}

async function waitForCondition(predicate, { timeoutMs = 7000, intervalMs = 50 } = {}) {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  assert.fail('Timed out waiting for condition.');
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
