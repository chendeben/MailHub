import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { DatabaseSync } from 'node:sqlite';
import {
  authenticateUser,
  claimLegacyData,
  createApiToken,
  createDomain,
  createUser,
  getSendAnalytics,
  getSmtpCredential,
  initDatabase,
  listDomains,
  listSendEvents,
  logSendEvent,
  saveSmtpCredential,
  seedAdminUser,
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
