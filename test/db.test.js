import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { DatabaseSync } from 'node:sqlite';
import {
  authenticateUser,
  claimLegacyData,
  consumeAccountToken,
  createApiToken,
  createAccountToken,
  createDomain,
  createUser,
  createUserWithAccountToken,
  deleteSmtpRelay,
  getDnsCredential,
  getDomain,
  getSendAnalytics,
  getSmtpRelay,
  getSmtpCredential,
  getAdminResourceInventory,
  getSystemEmailSettings,
  getUser,
  initDatabase,
  listAuditLogs,
  listDomains,
  listSendEvents,
  listSmtpRelays,
  listUsersWithResourceCounts,
  invalidateAccountTokens,
  logAudit,
  logSendEvent,
  approveUser,
  markUserEmailVerified,
  previewUserMerge,
  saveDnsCredential,
  saveSmtpRelay,
  saveSmtpCredential,
  saveSystemEmailSettings,
  seedAdminUser,
  transferApiTokens,
  transferDnsCredential,
  transferDomain,
  updateUser,
  updateUserStatus,
  executeUserMerge,
  verifyApiToken,
  verifySmtpCredential
} from '../src/db.js';

test('migrates legacy data to the seeded admin user', () => {
  const dataDir = tempDataDir();
  const dbPath = path.join(dataDir, 'mailhub.sqlite');
  const legacy = new DatabaseSync(dbPath);
  legacy.exec(`
    CREATE TABLE domains (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      domain TEXT NOT NULL UNIQUE,
      selector TEXT NOT NULL,
      verification_token TEXT NOT NULL,
      dkim_public TEXT NOT NULL,
      dkim_private TEXT NOT NULL,
      sender_host TEXT NOT NULL,
      sending_ip TEXT NOT NULL,
      spf_extra TEXT NOT NULL DEFAULT '',
      dmarc_policy TEXT NOT NULL DEFAULT 'none',
      dmarc_rua TEXT NOT NULL DEFAULT '',
      status_json TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE send_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      domain_id INTEGER,
      sender TEXT NOT NULL,
      recipients TEXT NOT NULL,
      subject TEXT NOT NULL,
      status TEXT NOT NULL,
      detail TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL
    );
    CREATE TABLE smtp_credentials (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      username TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      password_secret TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
  `);
  legacy
    .prepare(`
      INSERT INTO domains (
        domain, selector, verification_token, dkim_public, dkim_private,
        sender_host, sending_ip, spf_extra, dmarc_policy, dmarc_rua, created_at, updated_at
      ) VALUES ('legacy.example', 'mh', 'tok', 'pub', 'priv', 'mail.legacy.example', '127.0.0.1', '', 'none', '', 'now', 'now')
    `)
    .run();
  legacy
    .prepare(`
      INSERT INTO send_events (domain_id, sender, recipients, subject, status, detail, created_at)
      VALUES (1, 'noreply@legacy.example', '["user@example.com"]', 'hi', 'queued', '', 'now')
    `)
    .run();
  legacy
    .prepare(`
      INSERT INTO smtp_credentials (id, username, password_hash, password_secret, created_at, updated_at)
      VALUES (1, 'legacy-smtp', 'scrypt$salt$hash', '', 'now', 'now')
    `)
    .run();
  legacy.close();

  initDatabase(dataDir, 'test-secret');
  const admin = seedAdminUser({ username: 'admin', email: 'admin@example.com', password: 'password123' });
  claimLegacyData(admin.id);

  assert.equal(listDomains(admin.id).length, 1);
  assert.equal(listSendEvents(admin.id).length, 1);
  assert.equal(getSmtpCredential(admin.id).username, 'legacy-smtp');
});

test('isolates domains, smtp credentials, and api tokens by user', () => {
  initDatabase(tempDataDir(), 'test-secret');
  const admin = seedAdminUser({ username: 'admin', email: 'admin@example.com', password: 'password123' });
  claimLegacyData(admin.id);
  const alice = createUser({ username: 'alice', email: 'alice@example.com', password: 'password123' });
  const bob = createUser({ username: 'bob', email: 'bob@example.com', password: 'password123' });

  assert.equal(authenticateUser('alice', 'password123').id, alice.id);
  assert.equal(authenticateUser('alice', 'wrong'), null);

  createDomain(alice.id, domainFixture('alice.example'));
  assert.equal(listDomains(alice.id).length, 1);
  assert.equal(listDomains(bob.id).length, 0);

  logSendEvent({
    userId: alice.id,
    domainId: listDomains(alice.id)[0].id,
    sender: 'noreply@alice.example',
    recipients: ['user@example.com'],
    subject: 'Hello',
    status: 'queued'
  });
  assert.equal(listSendEvents(alice.id).length, 1);
  assert.equal(listSendEvents(bob.id).length, 0);

  saveSmtpCredential(alice.id, { username: 'smtp-alice', password: 'copy-me-123' });
  assert.equal(getSmtpCredential(alice.id, { includePassword: true }).password, 'copy-me-123');
  assert.equal(verifySmtpCredential('smtp-alice', 'copy-me-123').user.id, alice.id);
  assert.equal(verifySmtpCredential('smtp-alice', 'wrong'), null);

  const token = createApiToken(alice.id, 'send');
  assert.equal(verifyApiToken(token.token).id, alice.id);
});

test('stores multiple outbound smtp relays with encrypted recoverable passwords', () => {
  const database = initDatabase(tempDataDir(), 'test-secret');
  const alice = createUser({ username: 'alice', email: 'alice@example.com', password: 'password123' });
  const bob = createUser({ username: 'bob', email: 'bob@example.com', password: 'password123' });

  const primary = saveSmtpRelay(alice.id, {
    name: 'Primary relay',
    host: 'smtp.primary.example',
    port: 587,
    secure: false,
    username: 'primary-user',
    password: 'primary-secret',
    helo: 'mail.alice.example',
    isDefault: true
  });
  const backup = saveSmtpRelay(alice.id, {
    name: 'Backup relay',
    host: 'smtp.backup.example',
    port: 465,
    secure: true,
    username: 'backup-user',
    password: 'backup-secret',
    isDefault: true
  });
  saveSmtpRelay(bob.id, {
    name: 'Bob relay',
    host: 'smtp.bob.example',
    port: 25,
    secure: false,
    username: '',
    password: '',
    isDefault: true
  });

  assert.equal(primary.passwordSet, true);
  assert.equal('password' in primary, false);
  assert.deepEqual(
    listSmtpRelays(alice.id).map((relay) => [relay.name, relay.isDefault, 'password' in relay]),
    [
      ['Backup relay', true, false],
      ['Primary relay', false, false]
    ]
  );
  assert.equal(getSmtpRelay(backup.id, alice.id, { includePassword: true }).password, 'backup-secret');
  assert.equal(getSmtpRelay(backup.id, bob.id), null);
  assert.equal(JSON.stringify(listSmtpRelays(alice.id)).includes('backup-secret'), false);

  const stored = database.prepare('SELECT password_secret FROM smtp_relays WHERE id = ?').get(backup.id);
  assert.ok(stored.password_secret);
  assert.equal(stored.password_secret.includes('backup-secret'), false);

  const updated = saveSmtpRelay(alice.id, {
    id: backup.id,
    name: 'Backup relay updated',
    host: 'smtp.backup.example',
    port: 2525,
    secure: false,
    username: 'backup-user',
    helo: 'helo.backup.example',
    isDefault: false
  });
  assert.equal(updated.port, 2525);
  assert.equal(updated.isDefault, false);
  assert.equal(getSmtpRelay(backup.id, alice.id, { includePassword: true }).password, 'backup-secret');
  const cleared = saveSmtpRelay(alice.id, {
    id: backup.id,
    name: 'Backup relay without auth',
    host: 'smtp.backup.example',
    username: '',
    password: ''
  });
  assert.equal(cleared.passwordSet, false);
  assert.equal(getSmtpRelay(backup.id, alice.id, { includePassword: true }).password, '');
  assert.equal(saveSmtpRelay(bob.id, {
    id: backup.id,
    name: 'Should not create',
    host: 'smtp.invalid.example'
  }), null);
  assert.equal(deleteSmtpRelay(backup.id, bob.id), false);
  assert.equal(deleteSmtpRelay(backup.id, alice.id), true);
  assert.equal(getSmtpRelay(backup.id, alice.id), null);
});

test('stores account tokens as hashes and enforces token lifecycle', () => {
  const database = initDatabase(tempDataDir(), 'test-secret');
  const alice = createUser({ username: 'alice', email: 'alice@example.com', password: 'password123' });
  const bob = createUser({ username: 'bob', email: 'bob@example.com', password: 'password123' });
  const purpose = 'email_verification';
  const created = createAccountToken(alice.id, purpose, { ttlMinutes: 30 });
  const expectedHash = createHash('sha256').update(created.token).digest('hex');

  assert.equal(created.userId, alice.id);
  assert.equal(created.purpose, purpose);
  assert.equal(typeof created.token, 'string');
  assert.equal(created.token.length > 32, true);
  assert.equal(created.usedAt, null);
  assert.equal('tokenHash' in created, false);

  const stored = database.prepare('SELECT * FROM account_tokens WHERE id = ?').get(created.id);
  assert.equal(stored.user_id, alice.id);
  assert.equal(stored.purpose, purpose);
  assert.equal(stored.token_hash, expectedHash);
  assert.notEqual(stored.token_hash, created.token);
  assert.equal(Object.values(stored).includes(created.token), false);

  assert.equal(consumeAccountToken(created.token, 'password_reset'), null);
  const consumed = consumeAccountToken(created.token, purpose);
  assert.equal(consumed.id, created.id);
  assert.equal(consumed.userId, alice.id);
  assert.equal(consumed.purpose, purpose);
  assert.equal(typeof consumed.usedAt, 'string');
  assert.equal('token' in consumed, false);
  assert.equal(consumeAccountToken(created.token, purpose), null);

  const expired = createAccountToken(alice.id, purpose, { ttlMinutes: 30 });
  database
    .prepare('UPDATE account_tokens SET expires_at = ? WHERE id = ?')
    .run('2000-01-01T00:00:00.000Z', expired.id);
  assert.equal(consumeAccountToken(expired.token, purpose), null);

  const alreadyUsedReset = createAccountToken(alice.id, 'password_reset', { ttlMinutes: 30 });
  assert.equal(consumeAccountToken(alreadyUsedReset.token, 'password_reset').id, alreadyUsedReset.id);
  const reset = createAccountToken(alice.id, 'password_reset', { ttlMinutes: 30 });
  const otherPurpose = createAccountToken(alice.id, 'email_change', { ttlMinutes: 30 });
  const otherUserReset = createAccountToken(bob.id, 'password_reset', { ttlMinutes: 30 });

  assert.equal(invalidateAccountTokens(alice.id, 'password_reset'), 1);
  assert.equal(typeof database.prepare('SELECT used_at FROM account_tokens WHERE id = ?').get(reset.id).used_at, 'string');
  assert.equal(consumeAccountToken(reset.token, 'password_reset'), null);
  assert.equal(consumeAccountToken(alreadyUsedReset.token, 'password_reset'), null);
  assert.equal(consumeAccountToken(otherPurpose.token, 'email_change').id, otherPurpose.id);
  assert.equal(consumeAccountToken(otherUserReset.token, 'password_reset').id, otherUserReset.id);
});

test('password updates invalidate unused password reset tokens only', () => {
  initDatabase(tempDataDir(), 'test-secret');
  const alice = createUser({ username: 'alice', email: 'alice@example.com', password: 'password123' });
  const reset = createAccountToken(alice.id, 'password_reset', { ttlMinutes: 30 });
  const verification = createAccountToken(alice.id, 'email_verification', { ttlMinutes: 30 });

  updateUser(alice.id, { password: 'new-password-123' });

  assert.equal(consumeAccountToken(reset.token, 'password_reset'), null);
  assert.equal(consumeAccountToken(verification.token, 'email_verification').id, verification.id);
  assert.equal(authenticateUser('alice', 'password123'), null);
  assert.equal(authenticateUser('alice', 'new-password-123').id, alice.id);
});

test('validates account token ttl minute boundaries', () => {
  initDatabase(tempDataDir(), 'test-secret');
  const alice = createUser({ username: 'alice', email: 'alice@example.com', password: 'password123' });
  const maxTtlMinutes = 7 * 24 * 60;

  for (const ttlMinutes of [0, -1, 1.5, maxTtlMinutes + 1, Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.throws(
      () => createAccountToken(alice.id, 'email_verification', { ttlMinutes }),
      /令牌有效期不正确。/
    );
  }

  assert.equal(createAccountToken(alice.id, 'email_verification', { ttlMinutes: 1 }).userId, alice.id);
  assert.equal(createAccountToken(alice.id, 'password_reset', { ttlMinutes: maxTtlMinutes }).userId, alice.id);
});

test('creates users with account tokens atomically', () => {
  const database = initDatabase(tempDataDir(), 'test-secret');

  assert.throws(
    () => createUserWithAccountToken({
      username: 'rollback',
      email: 'rollback@example.com',
      password: 'password123',
      status: 'pending_email'
    }, 'email_verification', { ttlMinutes: 0 }),
    /令牌有效期不正确。/
  );
  assert.equal(
    database
      .prepare("SELECT COUNT(*) AS count FROM users WHERE username = 'rollback' OR email = 'rollback@example.com'")
      .get()
      .count,
    0
  );
  assert.equal(database.prepare('SELECT COUNT(*) AS count FROM account_tokens').get().count, 0);

  const { user, accountToken } = createUserWithAccountToken({
    username: 'atomic',
    email: 'atomic@example.com',
    password: 'password123',
    status: 'pending_email'
  }, 'email_verification', { ttlMinutes: 30 });

  assert.equal(user.status, 'pending_email');
  assert.equal(accountToken.userId, user.id);
  assert.equal(accountToken.purpose, 'email_verification');
  assert.equal(typeof accountToken.token, 'string');
  assert.equal('tokenHash' in accountToken, false);
  assert.equal(
    database
      .prepare('SELECT COUNT(*) AS count FROM account_tokens WHERE user_id = ? AND purpose = ?')
      .get(user.id, 'email_verification')
      .count,
    1
  );
});

test('moves users through the extended status lifecycle', () => {
  initDatabase(tempDataDir(), 'test-secret');
  const pendingEmail = createUser({
    username: 'pending',
    email: 'pending@example.com',
    password: 'password123',
    status: 'pending_email'
  });
  const seededAdmin = seedAdminUser({ username: 'admin', email: 'admin@example.com', password: 'password123' });

  assert.equal(pendingEmail.status, 'pending_email');
  assert.equal(seededAdmin.status, 'active');
  assert.equal(markUserEmailVerified(pendingEmail.id).status, 'pending_review');
  assert.equal(markUserEmailVerified(pendingEmail.id).status, 'pending_review');
  assert.equal(approveUser(pendingEmail.id).status, 'active');
  assert.equal(markUserEmailVerified(pendingEmail.id).status, 'active');
  assert.equal(updateUserStatus(pendingEmail.id, 'disabled').status, 'disabled');
  assert.equal(updateUser(pendingEmail.id, { status: 'pending_review' }).status, 'pending_review');

  assert.equal(markUserEmailVerified(999999), null);
  assert.throws(() => updateUserStatus(pendingEmail.id, 'archived'), /用户状态不正确/);
  assert.throws(
    () => createUser({
      username: 'invalidstatus',
      email: 'invalidstatus@example.com',
      password: 'password123',
      status: 'archived'
    }),
    /用户状态不正确/
  );
  assert.equal(getUser(pendingEmail.id).status, 'pending_review');
});

test('lists users with owned resource counts', () => {
  initDatabase(tempDataDir(), 'test-secret');
  const alice = createUser({ username: 'alice', email: 'alice@example.com', password: 'password123' });
  const bob = createUser({ username: 'bob', email: 'bob@example.com', password: 'password123' });
  const aliceDomain = createDomain(alice.id, domainFixture('alice.example'));
  createDomain(alice.id, domainFixture('news.alice.example'));
  const bobDomain = createDomain(bob.id, domainFixture('bob.example'));

  saveDnsCredential(alice.id, {
    name: 'Alice Cloudflare',
    provider: 'cloudflare',
    zoneName: 'alice.example',
    credentials: { apiToken: 'alice-secret-dns-token', zoneId: 'alice-zone' }
  });
  saveDnsCredential(alice.id, {
    name: 'Alice News Cloudflare',
    provider: 'cloudflare',
    zoneName: 'news.alice.example',
    credentials: { apiToken: 'alice-news-secret-dns-token', zoneId: 'alice-news-zone' }
  });

  createApiToken(alice.id, 'primary');
  createApiToken(alice.id, 'secondary');
  createApiToken(bob.id, 'primary');
  saveSmtpCredential(alice.id, { username: 'smtp-alice', password: 'smtp-secret-123' });

  logSendEvent({
    userId: alice.id,
    domainId: aliceDomain.id,
    sender: 'noreply@alice.example',
    recipients: ['one@example.com'],
    subject: 'First',
    status: 'queued'
  });
  logSendEvent({
    userId: alice.id,
    domainId: aliceDomain.id,
    sender: 'noreply@alice.example',
    recipients: ['two@example.com'],
    subject: 'Second',
    status: 'sent'
  });
  logSendEvent({
    userId: bob.id,
    domainId: bobDomain.id,
    sender: 'noreply@bob.example',
    recipients: ['bob@example.com'],
    subject: 'Bob',
    status: 'queued'
  });

  const users = listUsersWithResourceCounts();
  const aliceWithCounts = users.find((user) => user.id === alice.id);
  const bobWithCounts = users.find((user) => user.id === bob.id);

  assert.deepEqual(aliceWithCounts.resourceCounts, {
    domains: 2,
    dnsCredentials: 2,
    apiTokens: 2,
    sendEvents: 2,
    smtpCredential: 1
  });
  assert.deepEqual(bobWithCounts.resourceCounts, {
    domains: 1,
    dnsCredentials: 0,
    apiTokens: 1,
    sendEvents: 1,
    smtpCredential: 0
  });
  assert.equal(typeof aliceWithCounts.resourceCounts.domains, 'number');
  assert.equal('passwordHash' in aliceWithCounts, false);
  assert.equal(JSON.stringify(users).includes('alice-secret-dns-token'), false);
  assert.equal(JSON.stringify(users).includes('smtp-secret-123'), false);
});

test('builds admin resource inventory grouped by user with ownership warnings', () => {
  initDatabase(tempDataDir(), 'test-secret');
  const alice = createUser({ username: 'alice', email: 'alice@example.com', password: 'password123' });
  const bob = createUser({ username: 'bob', email: 'bob@example.com', password: 'password123' });
  const bobCredential = saveDnsCredential(bob.id, {
    name: 'Bob DNS',
    provider: 'cloudflare',
    zoneName: 'bob.example',
    credentials: { apiToken: 'bob-secret-token', zoneId: 'bob-zone' }
  });
  const aliceDomain = createDomain(alice.id, {
    ...domainFixture('alice.example'),
    dnsCredentialId: bobCredential.id
  });
  createDomain(bob.id, domainFixture('bob.example'));
  createApiToken(alice.id, 'primary');
  saveSmtpCredential(alice.id, { username: 'smtp-alice', password: 'smtp-secret-123' });
  logSendEvent({
    userId: alice.id,
    domainId: aliceDomain.id,
    sender: 'noreply@alice.example',
    recipients: ['a@example.com'],
    subject: 'Queued',
    status: 'queued'
  });

  const inventory = getAdminResourceInventory();
  const aliceResources = inventory.users.find((entry) => entry.user.id === alice.id);
  const bobResources = inventory.users.find((entry) => entry.user.id === bob.id);

  assert.equal(aliceResources.domains.length, 1);
  assert.equal(aliceResources.domains[0].domain, 'alice.example');
  assert.equal(aliceResources.dnsCredentials.length, 0);
  assert.equal(aliceResources.apiTokens.length, 1);
  assert.equal(aliceResources.smtpCredential.username, 'smtp-alice');
  assert.equal(aliceResources.smtpCredential.passwordSet, true);
  assert.equal(aliceResources.sendEventCount, 1);
  assert.equal(bobResources.domains.length, 1);
  assert.equal(bobResources.dnsCredentials.length, 1);
  assert.deepEqual(inventory.warnings, [{
    type: 'domain_dns_credential_owner_mismatch',
    domainId: aliceDomain.id,
    domain: 'alice.example',
    domainUserId: alice.id,
    dnsCredentialId: bobCredential.id,
    dnsCredentialUserId: bob.id
  }]);
  assert.equal(JSON.stringify(inventory).includes('bob-secret-token'), false);
  assert.equal(JSON.stringify(inventory).includes('smtp-secret-123'), false);
});

test('transfers individual resources with audit logs', () => {
  initDatabase(tempDataDir(), 'test-secret');
  const admin = createUser({ username: 'admin2', email: 'admin2@example.com', password: 'password123', role: 'admin' });
  const alice = createUser({ username: 'alice', email: 'alice@example.com', password: 'password123' });
  const bob = createUser({ username: 'bob', email: 'bob@example.com', password: 'password123' });
  const disabled = createUser({ username: 'disabled', email: 'disabled@example.com', password: 'password123', status: 'disabled' });
  const domainOnlyCredential = saveDnsCredential(alice.id, {
    name: 'Alice DNS 1',
    provider: 'cloudflare',
    zoneName: 'alice.example',
    credentials: { apiToken: 'alice-secret-1' }
  });
  const clearCredential = saveDnsCredential(alice.id, {
    name: 'Alice DNS 2',
    provider: 'cloudflare',
    zoneName: 'clear.example',
    credentials: { apiToken: 'alice-secret-2' }
  });
  const withCredential = saveDnsCredential(alice.id, {
    name: 'Alice DNS 3',
    provider: 'cloudflare',
    zoneName: 'with.example',
    credentials: { apiToken: 'alice-secret-3' }
  });
  const standaloneCredential = saveDnsCredential(alice.id, {
    name: 'Alice DNS 4',
    provider: 'cloudflare',
    zoneName: 'standalone.example',
    credentials: { apiToken: 'alice-secret-4' }
  });
  const domainOnly = createDomain(alice.id, { ...domainFixture('domain-only.example'), dnsCredentialId: domainOnlyCredential.id });
  const clearDomain = createDomain(alice.id, { ...domainFixture('clear.example'), dnsCredentialId: clearCredential.id });
  const withDomain = createDomain(alice.id, { ...domainFixture('with.example'), dnsCredentialId: withCredential.id });
  const apiToken = createApiToken(alice.id, 'primary');

  assert.equal(transferDomain({
    actorUserId: admin.id,
    domainId: domainOnly.id,
    targetUserId: bob.id,
    dnsCredentialMode: 'domain_only'
  }).userId, bob.id);
  assert.equal(getDomain(domainOnly.id).dnsCredentialId, domainOnlyCredential.id);
  assert.equal(getDnsCredential(domainOnlyCredential.id, alice.id).id, domainOnlyCredential.id);
  assert.throws(
    () => transferDomain({
      actorUserId: admin.id,
      domainId: domainOnly.id,
      targetUserId: bob.id,
      dnsCredentialMode: 'with_dns_credential'
    }),
    /DNS 凭据归属不一致。/
  );
  assert.equal(getDnsCredential(domainOnlyCredential.id, alice.id).id, domainOnlyCredential.id);

  assert.equal(transferDomain({
    actorUserId: admin.id,
    domainId: clearDomain.id,
    targetUserId: bob.id,
    dnsCredentialMode: 'clear_dns_credential'
  }).dnsCredentialId, null);
  assert.equal(getDnsCredential(clearCredential.id, alice.id).id, clearCredential.id);

  assert.equal(transferDomain({
    actorUserId: admin.id,
    domainId: withDomain.id,
    targetUserId: bob.id,
    dnsCredentialMode: 'with_dns_credential'
  }).userId, bob.id);
  assert.equal(getDnsCredential(withCredential.id, bob.id).id, withCredential.id);

  assert.equal(transferDnsCredential({
    actorUserId: admin.id,
    credentialId: standaloneCredential.id,
    targetUserId: bob.id
  }).userId, bob.id);
  assert.equal(getDnsCredential(standaloneCredential.id, bob.id).id, standaloneCredential.id);

  const transferredTokens = transferApiTokens({
    actorUserId: admin.id,
    tokenIds: [apiToken.id],
    targetUserId: bob.id
  });
  assert.equal(transferredTokens.length, 1);
  assert.equal(verifyApiToken(apiToken.token).id, bob.id);

  assert.throws(
    () => transferDomain({ actorUserId: admin.id, domainId: domainOnly.id, targetUserId: disabled.id }),
    /目标用户不可用。/
  );
  assert.throws(
    () => transferApiTokens({ actorUserId: admin.id, tokenIds: [apiToken.id], targetUserId: 999999 }),
    /目标用户不可用。/
  );

  const actions = listAuditLogs({ actorUserId: admin.id }).map((entry) => entry.action);
  assert.ok(actions.includes('admin.transfer_domain'));
  assert.ok(actions.includes('admin.transfer_dns_credential'));
  assert.ok(actions.includes('admin.transfer_api_tokens'));
  assert.equal(JSON.stringify(listAuditLogs({ actorUserId: admin.id })).includes('alice-secret'), false);
});

test('previews and executes user merge with resource counts and smtp conflict handling', () => {
  initDatabase(tempDataDir(), 'test-secret');
  const admin = createUser({ username: 'admin3', email: 'admin3@example.com', password: 'password123', role: 'admin' });
  const source = createUser({ username: 'source', email: 'source@example.com', password: 'password123' });
  const target = createUser({ username: 'target', email: 'target@example.com', password: 'password123' });
  const credential = saveDnsCredential(source.id, {
    name: 'Source DNS',
    provider: 'cloudflare',
    zoneName: 'source.example',
    credentials: { apiToken: 'source-secret' }
  });
  const domain = createDomain(source.id, { ...domainFixture('source.example'), dnsCredentialId: credential.id });
  const apiToken = createApiToken(source.id, 'primary');
  saveSmtpCredential(source.id, { username: 'smtp-source', password: 'source-secret-123' });
  saveSmtpCredential(target.id, { username: 'smtp-target', password: 'target-secret-123' });
  logSendEvent({
    userId: source.id,
    domainId: domain.id,
    sender: 'noreply@source.example',
    recipients: ['a@example.com'],
    subject: 'Queued',
    status: 'queued'
  });

  const preview = previewUserMerge({ sourceUserId: source.id, targetUserId: target.id });
  assert.equal(preview.confirmationText, 'MERGE source INTO target');
  assert.deepEqual(preview.counts, {
    domains: 1,
    dnsCredentials: 1,
    apiTokens: 1,
    sendEvents: 1,
    smtpCredential: 1
  });
  assert.equal(preview.resources.source.domains[0].domain, 'source.example');
  assert.equal(preview.resources.source.dnsCredentials[0].name, 'Source DNS');
  assert.equal(preview.resources.source.apiTokens[0].name, 'primary');
  assert.equal(preview.resources.source.sendEventCount, 1);
  assert.equal(preview.resources.target.domains.length, 0);
  assert.deepEqual(preview.selectedCounts, {
    domains: 1,
    dnsCredentials: 1,
    apiTokens: 1,
    sendEvents: 1,
    smtpCredential: 0
  });
  assert.equal(preview.smtp.conflict, true);
  assert.ok(preview.warnings.some((warning) => warning.type === 'smtp_credential_conflict'));

  assert.throws(
    () => executeUserMerge({
      actorUserId: admin.id,
      sourceUserId: source.id,
      targetUserId: target.id,
      confirmation: 'wrong'
    }),
    /确认文本不匹配。/
  );
  assert.equal(getDomain(domain.id).userId, source.id);

  const result = executeUserMerge({
    actorUserId: admin.id,
    sourceUserId: source.id,
    targetUserId: target.id,
    confirmation: preview.confirmationText
  });

  assert.deepEqual(result.counts, {
    domains: 1,
    dnsCredentials: 1,
    apiTokens: 1,
    sendEvents: 1,
    smtpCredential: 0
  });
  assert.equal(getDomain(domain.id).userId, target.id);
  assert.equal(getDnsCredential(credential.id, target.id).id, credential.id);
  assert.equal(verifyApiToken(apiToken.token).id, target.id);
  assert.equal(listSendEvents(target.id).length, 1);
  assert.equal(getSmtpCredential(target.id).username, 'smtp-target');
  assert.equal(getSmtpCredential(source.id).username, 'smtp-source');
  assert.equal(getUser(source.id).status, 'disabled');

  const [audit] = listAuditLogs({ action: 'admin.user_merge' });
  assert.equal(audit.targetUserId, target.id);
  assert.equal(audit.summary.sourceUserId, source.id);
  assert.deepEqual(audit.summary.counts, result.counts);
  assert.equal(JSON.stringify(audit).includes('source-secret'), false);
  assert.equal(JSON.stringify(audit).includes('target-secret'), false);
});

test('stores system email settings without exposing smtp password publicly', () => {
  const database = initDatabase(tempDataDir(), 'test-secret');

  const saved = saveSystemEmailSettings({
    host: 'smtp.example.com',
    port: 465,
    secure: true,
    username: 'mailer@example.com',
    password: 'smtp-password-123',
    helo: 'mail.example.com',
    fromEmail: 'notify@example.com',
    fromName: 'MailHub Notify',
    testRecipient: 'admin@example.com'
  });

  assert.equal(saved.host, 'smtp.example.com');
  assert.equal(saved.port, 465);
  assert.equal(saved.secure, true);
  assert.equal(saved.passwordSet, true);
  assert.equal('password' in saved, false);
  assert.equal(JSON.stringify(saved).includes('smtp-password-123'), false);

  const storedRows = database.prepare("SELECT key, value FROM app_settings WHERE key LIKE 'systemEmail.%'").all();
  assert.equal(storedRows.some((row) => row.value === 'smtp-password-123'), false);

  const publicSettings = getSystemEmailSettings();
  assert.equal(publicSettings.passwordSet, true);
  assert.equal('password' in publicSettings, false);
  assert.equal(JSON.stringify(publicSettings).includes('smtp-password-123'), false);

  const internalSettings = getSystemEmailSettings({ includeSecret: true });
  assert.equal(internalSettings.password, 'smtp-password-123');
  assert.equal(internalSettings.passwordSet, true);

  const unchangedPassword = saveSystemEmailSettings({
    host: 'smtp2.example.com',
    password: ''
  });
  assert.equal(unchangedPassword.host, 'smtp2.example.com');
  assert.equal(unchangedPassword.passwordSet, true);
  assert.equal(getSystemEmailSettings({ includeSecret: true }).password, 'smtp-password-123');
});

test('summarizes send analytics by user', () => {
  initDatabase(tempDataDir(), 'test-secret');
  const alice = createUser({ username: 'alice', email: 'alice@example.com', password: 'password123' });
  const bob = createUser({ username: 'bob', email: 'bob@example.com', password: 'password123' });
  const aliceDomain = createDomain(alice.id, domainFixture('alice.example'));
  const bobDomain = createDomain(bob.id, domainFixture('bob.example'));

  logSendEvent({
    userId: alice.id,
    domainId: aliceDomain.id,
    sender: 'noreply@alice.example',
    recipients: ['a@example.com', 'b@example.com'],
    subject: 'Queued',
    status: 'queued'
  });
  logSendEvent({
    userId: alice.id,
    domainId: aliceDomain.id,
    sender: 'noreply@alice.example',
    recipients: ['c@example.com'],
    subject: 'Failed',
    status: 'failed',
    detail: 'relay rejected'
  });
  logSendEvent({
    userId: bob.id,
    domainId: bobDomain.id,
    sender: 'noreply@bob.example',
    recipients: ['x@example.com'],
    subject: 'Hidden',
    status: 'queued'
  });

  const analytics = getSendAnalytics(alice.id, { days: 7 });
  assert.equal(analytics.summary.total, 2);
  assert.equal(analytics.summary.queued, 1);
  assert.equal(analytics.summary.failed, 1);
  assert.equal(analytics.summary.recipients, 3);
  assert.equal(analytics.summary.successRate, 50);
  assert.equal(analytics.byDomain.length, 1);
  assert.equal(analytics.byDomain[0].domain, 'alice.example');
  assert.equal(analytics.recentFailures.length, 1);
  assert.equal(analytics.recentFailures[0].detail, 'relay rejected');
});

test('excludes queued and sent messages from recent delivery failures', () => {
  initDatabase(tempDataDir(), 'test-secret');
  const alice = createUser({ username: 'alice', email: 'alice@example.com', password: 'password123' });
  const domain = createDomain(alice.id, domainFixture('alice.example'));
  for (const event of [
    { subject: 'Queued', status: 'queued', detail: 'accepted by postfix' },
    { subject: 'Sent', status: 'sent', detail: '250 OK' },
    { subject: 'Deferred', status: 'deferred', detail: 'temporary failure' },
    { subject: 'Bounced', status: 'bounced', detail: '550 user unknown' },
    { subject: 'Failed', status: 'failed', detail: 'relay rejected' }
  ]) {
    logSendEvent({
      userId: alice.id,
      domainId: domain.id,
      sender: 'noreply@alice.example',
      recipients: ['user@example.com'],
      subject: event.subject,
      status: event.status,
      detail: event.detail
    });
  }

  const analytics = getSendAnalytics(alice.id, { days: 7 });
  assert.deepEqual(
    analytics.recentFailures.map((event) => event.subject),
    ['Failed', 'Bounced', 'Deferred']
  );
});

test('stores and returns structured delivery logs for send events', () => {
  initDatabase(tempDataDir(), 'test-secret');
  const alice = createUser({ username: 'alice', email: 'alice@example.com', password: 'password123' });
  const domain = createDomain(alice.id, domainFixture('alice.example'));
  const deliveryLog = [
    {
      at: '2026-07-08T00:00:00.000Z',
      phase: 'connect',
      direction: 'system',
      message: 'Connected to relay.test:25',
      ok: true
    },
    {
      at: '2026-07-08T00:00:01.000Z',
      phase: 'queue',
      direction: 'server',
      code: 250,
      response: '250 queued as ABC123',
      ok: true
    }
  ];

  logSendEvent({
    userId: alice.id,
    domainId: domain.id,
    sender: 'noreply@alice.example',
    recipients: ['user@example.com'],
    subject: 'Delivery log',
    status: 'queued',
    detail: '250 queued as ABC123',
    deliveryLog
  });

  const [event] = listSendEvents(alice.id);
  assert.deepEqual(event.deliveryLog, deliveryLog);
});

test('records audit logs without storing secrets', () => {
  initDatabase(tempDataDir(), 'test-secret');
  const admin = createUser({ username: 'admin2', email: 'admin2@example.com', password: 'password123', role: 'admin' });
  const user = createUser({ username: 'alice', email: 'alice@example.com', password: 'password123' });

  logAudit({
    actorUserId: admin.id,
    action: 'admin.temporary_password',
    targetType: 'user',
    targetId: String(user.id),
    targetUserId: user.id,
    summary: {
      username: user.username,
      temporaryPassword: 'secret-password',
      passwordSet: true,
      dkimPrivate: 'private-key',
      dkimPublic: 'public-key',
      dkim_private: 'private-key',
      dkim_public: 'public-key',
      authorization: 'Bearer top-level-token',
      headers: {
        authorization: 'Bearer nested-token',
        from: 'admin@example.com'
      },
      nested: {
        apiToken: 'secret-token',
        note: 'kept'
      },
      changes: [
        {
          credential: 'secret-credential',
          field: 'password'
        },
        {
          field: 'password',
          value: 'plain-secret',
          label: 'password change'
        },
        {
          name: 'apiToken',
          oldValue: 'old-token',
          newValue: 'new-token'
        },
        {
          header: 'authorization',
          value: 'Bearer token',
          status: 'set'
        },
        {
          path: 'smtp.password',
          from: 'old-password',
          to: 'new-password'
        },
        {
          key: 'credentials.accessKeySecret',
          before: 'old-secret',
          after: 'new-secret'
        },
        {
          field: 'displayName',
          value: 'Alice Example'
        },
        {
          field: 'password',
          old: 'old-secret',
          new: 'new-secret'
        },
        {
          change: { field: 'password' },
          value: 'plain-secret'
        },
        {
          context: { path: 'smtp.password' },
          from: 'old-wrapper-secret',
          to: 'new-wrapper-secret'
        },
        {
          change: { field: 'displayName' },
          value: 'Alice Wrapper'
        }
      ]
    }
  });

  const [entry] = listAuditLogs({ actorUserId: admin.id });
  assert.equal(entry.action, 'admin.temporary_password');
  assert.equal(entry.targetType, 'user');
  assert.equal(entry.targetId, String(user.id));
  assert.equal(entry.targetUserId, user.id);
  assert.equal(entry.summary.username, 'alice');
  assert.equal(entry.summary.temporaryPassword, undefined);
  assert.equal(entry.summary.passwordSet, true);
  assert.equal(entry.summary.dkimPrivate, undefined);
  assert.equal(entry.summary.dkimPublic, 'public-key');
  assert.equal(entry.summary.dkim_private, undefined);
  assert.equal(entry.summary.dkim_public, 'public-key');
  assert.equal(entry.summary.authorization, undefined);
  assert.equal(entry.summary.headers.authorization, undefined);
  assert.equal(entry.summary.headers.from, 'admin@example.com');
  assert.equal(entry.summary.nested.apiToken, undefined);
  assert.equal(entry.summary.nested.note, 'kept');
  assert.equal(entry.summary.changes[0].credential, undefined);
  assert.equal(entry.summary.changes[0].field, 'password');
  assert.equal(entry.summary.changes[1].field, 'password');
  assert.equal(entry.summary.changes[1].value, undefined);
  assert.equal(entry.summary.changes[1].label, 'password change');
  assert.equal(entry.summary.changes[2].name, 'apiToken');
  assert.equal(entry.summary.changes[2].oldValue, undefined);
  assert.equal(entry.summary.changes[2].newValue, undefined);
  assert.equal(entry.summary.changes[3].header, 'authorization');
  assert.equal(entry.summary.changes[3].value, undefined);
  assert.equal(entry.summary.changes[3].status, 'set');
  assert.equal(entry.summary.changes[4].path, 'smtp.password');
  assert.equal(entry.summary.changes[4].from, undefined);
  assert.equal(entry.summary.changes[4].to, undefined);
  assert.equal(entry.summary.changes[5].key, undefined);
  assert.equal(entry.summary.changes[5].before, undefined);
  assert.equal(entry.summary.changes[5].after, undefined);
  assert.equal(entry.summary.changes[6].field, 'displayName');
  assert.equal(entry.summary.changes[6].value, 'Alice Example');
  assert.equal(entry.summary.changes[7].field, 'password');
  assert.equal(entry.summary.changes[7].old, undefined);
  assert.equal(entry.summary.changes[7].new, undefined);
  assert.deepEqual(entry.summary.changes[8].change, { field: 'password' });
  assert.equal(entry.summary.changes[8].value, undefined);
  assert.deepEqual(entry.summary.changes[9].context, { path: 'smtp.password' });
  assert.equal(entry.summary.changes[9].from, undefined);
  assert.equal(entry.summary.changes[9].to, undefined);
  assert.deepEqual(entry.summary.changes[10].change, { field: 'displayName' });
  assert.equal(entry.summary.changes[10].value, 'Alice Wrapper');
});

test('filters audit logs and returns newest entries first', () => {
  initDatabase(tempDataDir(), 'test-secret');
  const admin = createUser({ username: 'admin3', email: 'admin3@example.com', password: 'password123', role: 'admin' });
  const alice = createUser({ username: 'alice2', email: 'alice2@example.com', password: 'password123' });
  const bob = createUser({ username: 'bob2', email: 'bob2@example.com', password: 'password123' });

  logAudit({
    actorUserId: admin.id,
    action: 'admin.disable_user',
    targetType: 'user',
    targetId: String(alice.id),
    targetUserId: alice.id,
    summary: { username: alice.username }
  });
  logAudit({
    actorUserId: admin.id,
    action: 'admin.reset_password',
    targetType: 'user',
    targetId: String(alice.id),
    targetUserId: alice.id,
    summary: { username: alice.username }
  });
  logAudit({
    actorUserId: null,
    action: 'system.rotation',
    targetType: 'system',
    summary: { reason: 'scheduled' }
  });
  logAudit({
    actorUserId: admin.id,
    action: 'admin.reset_password',
    targetType: 'user',
    targetId: String(bob.id),
    targetUserId: bob.id,
    summary: { username: bob.username }
  });

  assert.deepEqual(
    listAuditLogs({ action: 'admin.reset_password' }).map((entry) => entry.summary.username),
    ['bob2', 'alice2']
  );
  assert.deepEqual(
    listAuditLogs({ targetUserId: alice.id }).map((entry) => entry.action),
    ['admin.reset_password', 'admin.disable_user']
  );
  assert.deepEqual(
    listAuditLogs({ actorUserId: null }).map((entry) => entry.action),
    ['system.rotation']
  );
  const pastIso = '2000-01-01T00:00:00.000Z';
  const futureIso = '2999-01-01T00:00:00.000Z';
  assert.deepEqual(listAuditLogs({ from: futureIso }), []);
  assert.deepEqual(listAuditLogs({ to: pastIso }), []);
  assert.deepEqual(
    listAuditLogs({ from: pastIso, to: futureIso }).map((entry) => entry.action),
    ['admin.reset_password', 'system.rotation', 'admin.reset_password', 'admin.disable_user']
  );
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
