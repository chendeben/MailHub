import { mkdirSync } from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { dkimPublicFromPrivateKey } from './dkim.js';
import { decryptTrackingTarget, hashTrackingToken } from './tracking.js';
import {
  MAX_WEBHOOK_ATTEMPTS,
  WEBHOOK_LEASE_MS,
  buildWebhookPayload,
  eventTypeForStatus,
  isTerminalWebhookStatus,
  nextBackoffMs,
  normalizeWebhookEvents,
  parseWebhookEventsJson,
  resolveWebhooksForEvent
} from './webhook-model.js';

let db;
let secretKey = '';
export const USER_STATUSES = new Set(['pending_email', 'pending_review', 'active', 'disabled']);
export const STANDARD_INBOUND_FOLDERS = ['INBOX', 'Sent', 'Drafts', 'Trash', 'Junk', 'Archive'];
export const API_TOKEN_SCOPES = new Set(['send', 'mailboxes:read', 'mailboxes:write']);
const auditSecretKeyPattern = /password|secret|token|key|credential|dkim[_-]?private|authorization/i;
const auditDescriptorKeyPattern = /^(field|name|path|key|header)$/i;
const auditDescriptorValuePattern = /password|secret|token|key|credential|dkim[_-]?private|authorization/i;
const auditDescriptorWrapperKeyPattern = /^(change|context|descriptor|meta)$/i;
const auditValueLikeKeyPattern = /^(value|from|to|old|new|old_?value|new_?value|before|after)$/i;
const maxAccountTokenTtlMinutes = 7 * 24 * 60;
const defaultApiTokenScopes = ['send'];

export function initDatabase(dataDir, secret = '') {
  secretKey = String(secret || process.env.SESSION_SECRET || process.env.API_TOKEN || process.env.ADMIN_PASSWORD || '');
  mkdirSync(dataDir, { recursive: true });
  db = new DatabaseSync(path.join(dataDir, 'mailhub.sqlite'));
  db.function('normalize_failure_reason', { deterministic: true }, (detail, status) => (
    String(detail || '').replace(/\s+/g, ' ').trim() || String(status || 'unknown failure')
  ));
  db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');
  migrateLegacySmtpTable();
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS domains (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      dns_credential_id INTEGER,
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
      catch_all_address TEXT NOT NULL DEFAULT '',
      status_json TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS send_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      domain_id INTEGER,
      sender TEXT NOT NULL,
      recipients TEXT NOT NULL,
      subject TEXT NOT NULL,
      status TEXT NOT NULL,
      detail TEXT NOT NULL DEFAULT '',
      queue_id TEXT NOT NULL DEFAULT '',
      delivery_log_json TEXT NOT NULL DEFAULT '[]',
      delivery_attempts_json TEXT NOT NULL DEFAULT '[]',
      delivered_at TEXT,
      tracking_token_hash TEXT,
      tracking_opens TEXT NOT NULL DEFAULT 'false',
      tracking_clicks TEXT NOT NULL DEFAULT 'false',
      created_at TEXT NOT NULL,
      FOREIGN KEY(domain_id) REFERENCES domains(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS tracking_links (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      send_event_id INTEGER NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      target_ciphertext TEXT NOT NULL,
      target_fingerprint TEXT NOT NULL,
      target_origin TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY(send_event_id) REFERENCES send_events(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS tracking_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      send_event_id INTEGER NOT NULL,
      tracking_link_id INTEGER,
      event_type TEXT NOT NULL,
      source TEXT NOT NULL,
      occurred_at TEXT NOT NULL,
      user_agent TEXT NOT NULL DEFAULT '',
      ip_hash TEXT NOT NULL,
      replay_key TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL,
      FOREIGN KEY(send_event_id) REFERENCES send_events(id) ON DELETE CASCADE,
      FOREIGN KEY(tracking_link_id) REFERENCES tracking_links(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      actor_user_id INTEGER,
      action TEXT NOT NULL,
      target_type TEXT NOT NULL,
      target_id TEXT NOT NULL DEFAULT '',
      target_user_id INTEGER,
      summary_json TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS smtp_credentials (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      password_secret TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS smtp_relays (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      host TEXT NOT NULL,
      port INTEGER NOT NULL DEFAULT 587,
      secure TEXT NOT NULL DEFAULT 'false',
      username TEXT NOT NULL DEFAULT '',
      password_secret TEXT NOT NULL DEFAULT '',
      helo TEXT NOT NULL DEFAULT '',
      is_default TEXT NOT NULL DEFAULT 'false',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS inbound_mailboxes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      domain_id INTEGER NOT NULL,
      address TEXT NOT NULL UNIQUE,
      local_part TEXT NOT NULL,
      display_name TEXT NOT NULL DEFAULT '',
      password_hash TEXT NOT NULL DEFAULT '',
      password_secret TEXT NOT NULL DEFAULT '',
      aliases_json TEXT NOT NULL DEFAULT '[]',
      forward_to_json TEXT NOT NULL DEFAULT '[]',
      keep_forwarded TEXT NOT NULL DEFAULT 'true',
      quota_mb INTEGER,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      deleted_at TEXT,
      expires_at TEXT,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(domain_id) REFERENCES domains(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS inbound_messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      mailbox_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      domain_id INTEGER NOT NULL,
      folder TEXT NOT NULL DEFAULT 'INBOX',
      sender TEXT NOT NULL DEFAULT '',
      recipients_json TEXT NOT NULL DEFAULT '[]',
      subject TEXT NOT NULL DEFAULT '',
      message_id TEXT NOT NULL DEFAULT '',
      raw_message TEXT NOT NULL DEFAULT '',
      text_body TEXT NOT NULL DEFAULT '',
      html_body TEXT NOT NULL DEFAULT '',
      preview TEXT NOT NULL DEFAULT '',
      read_state TEXT NOT NULL DEFAULT 'false',
      received_at TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      deleted_at TEXT,
      FOREIGN KEY(mailbox_id) REFERENCES inbound_mailboxes(id) ON DELETE CASCADE,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(domain_id) REFERENCES domains(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS inbound_folders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      mailbox_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      subscribed TEXT NOT NULL DEFAULT 'true',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      deleted_at TEXT,
      UNIQUE(mailbox_id, name),
      FOREIGN KEY(mailbox_id) REFERENCES inbound_mailboxes(id) ON DELETE CASCADE,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS api_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      token_prefix TEXT NOT NULL,
      scopes_json TEXT NOT NULL DEFAULT '["send"]',
      expires_at TEXT,
      revoked_at TEXT,
      revoked_reason TEXT NOT NULL DEFAULT '',
      last_used_at TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS account_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      purpose TEXT NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      expires_at TEXT NOT NULL,
      used_at TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS dns_credentials (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      provider TEXT NOT NULL,
      zone_name TEXT NOT NULL DEFAULT '',
      default_ttl INTEGER NOT NULL DEFAULT 600,
      credentials_secret TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS app_settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS webhooks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      domain_id INTEGER,
      name TEXT NOT NULL,
      url TEXT NOT NULL,
      secret_ciphertext TEXT NOT NULL,
      secret_prefix TEXT NOT NULL,
      events_json TEXT NOT NULL,
      enabled TEXT NOT NULL DEFAULT 'true',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS webhook_deliveries (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      webhook_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      send_event_id INTEGER NOT NULL,
      event_type TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      status TEXT NOT NULL,
      attempt_count INTEGER NOT NULL DEFAULT 0,
      next_attempt_at TEXT NOT NULL,
      last_attempt_at TEXT,
      response_status INTEGER,
      response_body_preview TEXT NOT NULL DEFAULT '',
      error TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL,
      FOREIGN KEY(webhook_id) REFERENCES webhooks(id) ON DELETE CASCADE,
      UNIQUE(webhook_id, send_event_id, event_type)
    );

    CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON api_tokens(user_id);
    CREATE INDEX IF NOT EXISTS idx_account_tokens_user_purpose ON account_tokens(user_id, purpose);
    CREATE INDEX IF NOT EXISTS idx_account_tokens_expires_at ON account_tokens(expires_at);
    CREATE INDEX IF NOT EXISTS idx_dns_credentials_user_id ON dns_credentials(user_id);
    CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
    CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_user_id ON audit_logs(actor_user_id);
    CREATE INDEX IF NOT EXISTS idx_audit_logs_target_user_id ON audit_logs(target_user_id);
    CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
    CREATE INDEX IF NOT EXISTS idx_webhooks_user_id ON webhooks(user_id);
    CREATE INDEX IF NOT EXISTS idx_webhooks_user_domain ON webhooks(user_id, domain_id);
    CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_status_next ON webhook_deliveries(status, next_attempt_at);
    CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_user_created ON webhook_deliveries(user_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_tracking_links_event ON tracking_links(send_event_id);
    CREATE INDEX IF NOT EXISTS idx_tracking_links_fingerprint ON tracking_links(target_fingerprint);
    CREATE INDEX IF NOT EXISTS idx_tracking_events_event_time ON tracking_events(send_event_id, occurred_at);
    CREATE INDEX IF NOT EXISTS idx_tracking_events_link_time ON tracking_events(tracking_link_id, occurred_at);
    CREATE INDEX IF NOT EXISTS idx_tracking_events_type_time ON tracking_events(event_type, occurred_at);
    CREATE INDEX IF NOT EXISTS idx_inbound_mailboxes_user_id ON inbound_mailboxes(user_id);
    CREATE INDEX IF NOT EXISTS idx_inbound_mailboxes_domain_id ON inbound_mailboxes(domain_id);
    CREATE INDEX IF NOT EXISTS idx_inbound_messages_user_received ON inbound_messages(user_id, received_at);
    CREATE INDEX IF NOT EXISTS idx_inbound_messages_mailbox_received ON inbound_messages(mailbox_id, received_at);
    CREATE INDEX IF NOT EXISTS idx_inbound_folders_mailbox ON inbound_folders(mailbox_id, deleted_at);
  `);
  ensureColumn('domains', 'user_id', 'INTEGER');
  ensureColumn('domains', 'dns_credential_id', 'INTEGER');
  ensureColumn('domains', 'smtp_relay_id', 'INTEGER');
  ensureColumn('domains', 'catch_all_address', "TEXT NOT NULL DEFAULT ''");
  ensureColumn('send_events', 'user_id', 'INTEGER');
  ensureColumn('send_events', 'smtp_relay_id', 'INTEGER');
  ensureColumn('send_events', 'queue_id', "TEXT NOT NULL DEFAULT ''");
  ensureColumn('send_events', 'delivery_log_json', "TEXT NOT NULL DEFAULT '[]'");
  ensureColumn('send_events', 'delivery_attempts_json', "TEXT NOT NULL DEFAULT '[]'");
  ensureColumn('send_events', 'delivered_at', 'TEXT');
  ensureColumn('send_events', 'tracking_token_hash', 'TEXT');
  ensureColumn('send_events', 'tracking_opens', "TEXT NOT NULL DEFAULT 'false'");
  ensureColumn('send_events', 'tracking_clicks', "TEXT NOT NULL DEFAULT 'false'");
  migrateSmtpCredentialsToMultiplePerUser();
  ensureColumn('smtp_credentials', 'password_secret', "TEXT NOT NULL DEFAULT ''");
  ensureColumn('inbound_mailboxes', 'password_hash', "TEXT NOT NULL DEFAULT ''");
  ensureColumn('inbound_mailboxes', 'password_secret', "TEXT NOT NULL DEFAULT ''");
  ensureColumn('inbound_mailboxes', 'aliases_json', "TEXT NOT NULL DEFAULT '[]'");
  ensureColumn('inbound_mailboxes', 'forward_to_json', "TEXT NOT NULL DEFAULT '[]'");
  ensureColumn('inbound_mailboxes', 'keep_forwarded', "TEXT NOT NULL DEFAULT 'true'");
  ensureColumn('inbound_mailboxes', 'quota_mb', 'INTEGER');
  ensureColumn('inbound_mailboxes', 'expires_at', 'TEXT');
  ensureColumn('inbound_messages', 'folder', "TEXT NOT NULL DEFAULT 'INBOX'");
  ensureColumn('api_tokens', 'scopes_json', "TEXT NOT NULL DEFAULT '[\"send\"]'");
  ensureColumn('api_tokens', 'expires_at', 'TEXT');
  ensureColumn('api_tokens', 'revoked_at', 'TEXT');
  ensureColumn('api_tokens', 'revoked_reason', "TEXT NOT NULL DEFAULT ''");
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_domains_user_id ON domains(user_id);
    CREATE INDEX IF NOT EXISTS idx_domains_smtp_relay_id ON domains(smtp_relay_id);
    CREATE INDEX IF NOT EXISTS idx_events_user_id ON send_events(user_id);
    CREATE INDEX IF NOT EXISTS idx_events_user_created ON send_events(user_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_events_smtp_relay_id ON send_events(smtp_relay_id);
    CREATE INDEX IF NOT EXISTS idx_events_queue_id ON send_events(queue_id);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_events_tracking_token_hash
      ON send_events(tracking_token_hash)
      WHERE tracking_token_hash IS NOT NULL AND tracking_token_hash != '';
    CREATE INDEX IF NOT EXISTS idx_smtp_credentials_user_id ON smtp_credentials(user_id);
    CREATE INDEX IF NOT EXISTS idx_smtp_relays_user_id ON smtp_relays(user_id);
    CREATE INDEX IF NOT EXISTS idx_api_tokens_user_status ON api_tokens(user_id, revoked_at, expires_at);
    CREATE INDEX IF NOT EXISTS idx_inbound_messages_mailbox_folder_received ON inbound_messages(mailbox_id, folder, received_at);
    CREATE INDEX IF NOT EXISTS idx_inbound_folders_mailbox ON inbound_folders(mailbox_id, deleted_at);
  `);
  normalizeSendEventQueueIds();
  normalizeDkimPublicKeys();
  return db;
}

export function seedAdminUser({ username, password, email }) {
  const normalizedUsername = normalizeUsername(username || 'admin');
  const normalizedEmail = normalizeEmail(email || `${normalizedUsername}@mailhub.local`);
  const existing = getUserByLogin(normalizedUsername) || getUserByLogin(normalizedEmail);
  if (existing) {
    requireDb()
      .prepare('UPDATE users SET role = ?, status = ?, updated_at = ? WHERE id = ?')
      .run('admin', 'active', now(), existing.id);
    return getUser(existing.id);
  }
  return createUser({
    username: normalizedUsername,
    email: normalizedEmail,
    password,
    role: 'admin',
    status: 'active'
  });
}

export function claimLegacyData(userId) {
  requireDb().prepare('UPDATE domains SET user_id = ? WHERE user_id IS NULL').run(userId);
  requireDb().prepare(`
    UPDATE send_events
    SET user_id = COALESCE((SELECT user_id FROM domains WHERE domains.id = send_events.domain_id), ?)
    WHERE user_id IS NULL
  `).run(userId);
  if (!tableExists('smtp_credentials_legacy') || getSmtpCredential(userId)) return;
  const legacy = requireDb().prepare('SELECT * FROM smtp_credentials_legacy WHERE id = 1').get();
  if (!legacy?.username || !legacy?.password_hash) return;
  const createdAt = now();
  requireDb()
    .prepare(`
      INSERT INTO smtp_credentials (user_id, username, password_hash, password_secret, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `)
    .run(userId, legacy.username, legacy.password_hash, legacy.password_secret || '', createdAt, createdAt);
}

export function seedSmtpCredential(userId, username, password) {
  if (!userId || !username || !password || getSmtpCredential(userId)) return null;
  return saveSmtpCredential(userId, { username, password });
}

export function createUser({ username, email, password, role = 'user', status = 'active' }) {
  const cleanUsername = normalizeUsername(username);
  const cleanEmail = normalizeEmail(email);
  const cleanStatus = normalizeUserStatus(status);
  if (!cleanUsername) throw new Error('用户名格式不正确。');
  if (!cleanEmail) throw new Error('邮箱格式不正确。');
  if (String(password || '').length < 8) throw new Error('密码至少需要 8 位。');
  const createdAt = now();
  const result = requireDb()
    .prepare(`
      INSERT INTO users (username, email, password_hash, role, status, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `)
    .run(cleanUsername, cleanEmail, hashPassword(password), role === 'admin' ? 'admin' : 'user', cleanStatus, createdAt, createdAt);
  return getUser(result.lastInsertRowid);
}

export function createUserWithAccountToken(userInput, tokenPurpose, { ttlMinutes } = {}) {
  const database = requireDb();
  database.exec('BEGIN');
  try {
    const user = createUser(userInput);
    const accountToken = createAccountToken(user.id, tokenPurpose, { ttlMinutes });
    database.exec('COMMIT');
    return { user, accountToken };
  } catch (error) {
    database.exec('ROLLBACK');
    throw error;
  }
}

export function authenticateUser(login, password) {
  const user = verifyUserCredentials(login, password);
  return user?.status === 'active' ? user : null;
}

export function verifyUserCredentials(login, password) {
  const user = getUserByLogin(login, { includeHash: true });
  if (!user || !verifyPassword(password, user.passwordHash)) return null;
  return publicUser(user);
}

export function listUsers() {
  return requireDb()
    .prepare('SELECT * FROM users ORDER BY created_at DESC')
    .all()
    .map(publicUser);
}

export function listUsersWithResourceCounts() {
  return requireDb()
    .prepare(`
      SELECT
        users.*,
        (SELECT COUNT(*) FROM domains WHERE domains.user_id = users.id) AS domains_count,
        (SELECT COUNT(*) FROM dns_credentials WHERE dns_credentials.user_id = users.id) AS dns_credentials_count,
        (SELECT COUNT(*) FROM api_tokens WHERE api_tokens.user_id = users.id) AS api_tokens_count,
        (SELECT COUNT(*) FROM inbound_mailboxes WHERE inbound_mailboxes.user_id = users.id AND inbound_mailboxes.deleted_at IS NULL) AS inbound_mailboxes_count,
        (SELECT COUNT(*) FROM inbound_messages WHERE inbound_messages.user_id = users.id AND inbound_messages.deleted_at IS NULL) AS inbound_messages_count,
        (SELECT COUNT(*) FROM send_events WHERE send_events.user_id = users.id) AS send_events_count,
        (SELECT COUNT(*) FROM smtp_credentials WHERE smtp_credentials.user_id = users.id) AS smtp_credentials_count
      FROM users
      ORDER BY users.created_at DESC
    `)
    .all()
    .map((row) => ({
      ...publicUser(row),
      resourceCounts: {
        domains: Number(row.domains_count || 0),
        dnsCredentials: Number(row.dns_credentials_count || 0),
        apiTokens: Number(row.api_tokens_count || 0),
        inboundMailboxes: Number(row.inbound_mailboxes_count || 0),
        inboundMessages: Number(row.inbound_messages_count || 0),
        sendEvents: Number(row.send_events_count || 0),
        smtpCredential: Number(row.smtp_credentials_count || 0)
      }
    }));
}

export function getAdminResourceInventory() {
  const users = listUsersWithResourceCounts();
  const domains = requireDb()
    .prepare('SELECT * FROM domains ORDER BY user_id, created_at DESC')
    .all()
    .map(publicDomainRow);
  const dnsCredentials = requireDb()
    .prepare('SELECT * FROM dns_credentials ORDER BY user_id, created_at DESC')
    .all()
    .map(publicDnsCredential);
  const smtpCredentials = requireDb()
    .prepare('SELECT * FROM smtp_credentials ORDER BY user_id')
    .all()
    .map(publicSmtpCredential);
  const apiTokens = requireDb()
    .prepare('SELECT * FROM api_tokens ORDER BY user_id, created_at DESC')
    .all()
    .map(publicApiToken);
  const inboundMailboxes = requireDb()
    .prepare(`
      SELECT
        m.*,
        d.domain,
        COUNT(msg.id) AS message_count,
        COALESCE(SUM(CASE WHEN msg.read_state = 'false' THEN 1 ELSE 0 END), 0) AS unread_count,
        MAX(msg.received_at) AS last_message_at
      FROM inbound_mailboxes m
      JOIN domains d ON d.id = m.domain_id
      LEFT JOIN inbound_messages msg ON msg.mailbox_id = m.id AND msg.deleted_at IS NULL
      WHERE m.deleted_at IS NULL
      GROUP BY m.id
      ORDER BY m.user_id, COALESCE(last_message_at, m.created_at) DESC, m.id DESC
    `)
    .all()
    .map(publicInboundMailbox);
  const sendEventCounts = new Map(
    requireDb()
      .prepare('SELECT user_id, COUNT(*) AS count FROM send_events GROUP BY user_id')
      .all()
      .map((row) => [row.user_id, Number(row.count || 0)])
  );
  const inboundMessageCounts = new Map(
    requireDb()
      .prepare('SELECT user_id, COUNT(*) AS count FROM inbound_messages WHERE deleted_at IS NULL GROUP BY user_id')
      .all()
      .map((row) => [row.user_id, Number(row.count || 0)])
  );
  const dnsCredentialById = new Map(dnsCredentials.map((credential) => [credential.id, credential]));

  return {
    users: users.map((user) => ({
      user,
      domains: domains.filter((domain) => domain.userId === user.id),
      dnsCredentials: dnsCredentials.filter((credential) => credential.userId === user.id),
      smtpCredential: smtpCredentials.find((credential) => credential.userId === user.id) || null,
      apiTokens: apiTokens.filter((token) => token.userId === user.id),
      inboundMailboxes: inboundMailboxes.filter((mailbox) => mailbox.userId === user.id),
      inboundMessageCount: inboundMessageCounts.get(user.id) || 0,
      sendEventCount: sendEventCounts.get(user.id) || 0
    })),
    warnings: domains.flatMap((domain) => {
      if (!domain.dnsCredentialId) return [];
      const credential = dnsCredentialById.get(domain.dnsCredentialId);
      if (!credential || credential.userId === domain.userId) return [];
      return [{
        type: 'domain_dns_credential_owner_mismatch',
        domainId: domain.id,
        domain: domain.domain,
        domainUserId: domain.userId,
        dnsCredentialId: credential.id,
        dnsCredentialUserId: credential.userId
      }];
    })
  };
}

export function transferDomain({ actorUserId, domainId, targetUserId, dnsCredentialMode = 'domain_only' }) {
  return withTransaction(() => {
    const target = requireTransferTargetUser(targetUserId);
    const domain = requireDomainRow(domainId);
    const mode = normalizeDnsCredentialTransferMode(dnsCredentialMode);
    const nextDnsCredentialId = mode === 'clear_dns_credential' ? null : domain.dns_credential_id;
    requireDb()
      .prepare('UPDATE domains SET user_id = ?, dns_credential_id = ?, updated_at = ? WHERE id = ?')
      .run(target.id, nextDnsCredentialId, now(), domain.id);
    const inboundCounts = moveInboundDomainResources(domain.id, target.id);
    if (mode === 'with_dns_credential' && domain.dns_credential_id) {
      const credential = requireDnsCredentialRow(domain.dns_credential_id);
      if (credential.user_id !== domain.user_id) throw new Error('DNS 凭据归属不一致。');
      requireDb()
        .prepare('UPDATE dns_credentials SET user_id = ?, updated_at = ? WHERE id = ?')
        .run(target.id, now(), domain.dns_credential_id);
    }
    const updated = getDomain(domain.id);
    logAudit({
      actorUserId,
      action: 'admin.transfer_domain',
      targetType: 'domain',
      targetId: String(domain.id),
      targetUserId: target.id,
      summary: {
        domain: domain.domain,
        fromUserId: domain.user_id,
        toUserId: target.id,
        dnsCredentialMode: mode,
        dnsCredentialId: domain.dns_credential_id || null,
        inboundMailboxes: inboundCounts.mailboxes,
        inboundMessages: inboundCounts.messages
      }
    });
    return updated;
  });
}

export function transferDnsCredential({ actorUserId, credentialId, targetUserId }) {
  return withTransaction(() => {
    const target = requireTransferTargetUser(targetUserId);
    const credential = requireDnsCredentialRow(credentialId);
    requireDb()
      .prepare('UPDATE dns_credentials SET user_id = ?, updated_at = ? WHERE id = ?')
      .run(target.id, now(), credential.id);
    const updated = publicDnsCredential(requireDnsCredentialRow(credential.id));
    logAudit({
      actorUserId,
      action: 'admin.transfer_dns_credential',
      targetType: 'dns_credential',
      targetId: String(credential.id),
      targetUserId: target.id,
      summary: {
        name: credential.name,
        provider: credential.provider,
        fromUserId: credential.user_id,
        toUserId: target.id
      }
    });
    return updated;
  });
}

export function transferApiTokens({ actorUserId, tokenIds, targetUserId }) {
  return withTransaction(() => {
    const target = requireTransferTargetUser(targetUserId);
    const ids = uniquePositiveIds(tokenIds);
    if (!ids.length) throw new Error('API Token 不存在。');
    const placeholders = ids.map(() => '?').join(', ');
    const tokens = requireDb()
      .prepare(`SELECT * FROM api_tokens WHERE id IN (${placeholders})`)
      .all(...ids);
    if (tokens.length !== ids.length) throw new Error('API Token 不存在。');
    requireDb()
      .prepare(`UPDATE api_tokens SET user_id = ? WHERE id IN (${placeholders})`)
      .run(target.id, ...ids);
    const updated = requireDb()
      .prepare(`SELECT * FROM api_tokens WHERE id IN (${placeholders}) ORDER BY created_at DESC`)
      .all(...ids)
      .map(publicApiToken);
    logAudit({
      actorUserId,
      action: 'admin.transfer_api_tokens',
      targetType: 'api_token',
      targetId: ids.join(','),
      targetUserId: target.id,
      summary: {
        tokenIds: ids,
        count: ids.length,
        fromUserIds: [...new Set(tokens.map((token) => token.user_id))],
        toUserId: target.id
      }
    });
    return updated;
  });
}

export function previewUserMerge({ sourceUserId, targetUserId }) {
  const { source, target } = requireMergeUsers(sourceUserId, targetUserId);
  const sourceSmtpCredentials = listSmtpCredentials(source.id);
  const targetSmtpCredentials = listSmtpCredentials(target.id);
  const sourceSmtp = sourceSmtpCredentials[0] || null;
  const targetSmtp = targetSmtpCredentials[0] || null;
  const counts = {
    domains: countRows('domains', source.id),
    dnsCredentials: countRows('dns_credentials', source.id),
    apiTokens: countRows('api_tokens', source.id),
    inboundMailboxes: countRows('inbound_mailboxes', source.id, 'deleted_at IS NULL'),
    inboundMessages: countRows('inbound_messages', source.id, 'deleted_at IS NULL'),
    sendEvents: countRows('send_events', source.id),
    smtpCredential: sourceSmtpCredentials.length
  };
  const defaultOptions = {
    transferDomains: true,
    transferDnsCredentials: true,
    transferApiTokens: true,
    transferSendEvents: true,
    transferSmtpCredential: sourceSmtpCredentials.length > 0,
    disableSource: true
  };
  const selectedCounts = {
    domains: counts.domains,
    dnsCredentials: counts.dnsCredentials,
    apiTokens: counts.apiTokens,
    inboundMailboxes: defaultOptions.transferDomains ? counts.inboundMailboxes : 0,
    inboundMessages: defaultOptions.transferDomains ? counts.inboundMessages : 0,
    sendEvents: counts.sendEvents,
    smtpCredential: defaultOptions.transferSmtpCredential ? counts.smtpCredential : 0
  };
  return {
    sourceUser: source,
    targetUser: target,
    confirmationText: `MERGE ${source.username} INTO ${target.username}`,
    counts,
    selectedCounts,
    defaultOptions,
    resources: {
      source: mergeResourcesForUser(source.id),
      target: mergeResourcesForUser(target.id)
    },
    smtp: {
      sourceCredential: sourceSmtp,
      targetCredential: targetSmtp,
      conflict: false
    },
    warnings: []
  };
}

export function executeUserMerge({ actorUserId, sourceUserId, targetUserId, options = {}, confirmation }) {
  return withTransaction(() => {
    const preview = previewUserMerge({ sourceUserId, targetUserId });
    if (confirmation !== preview.confirmationText) throw new Error('确认文本不匹配。');
    const sourceId = preview.sourceUser.id;
    const targetId = preview.targetUser.id;
    const inboundCounts = options.transferDomains === false
      ? { mailboxes: 0, messages: 0 }
      : moveInboundResourcesForUserDomains(sourceId, targetId);
    const counts = {
      domains: options.transferDomains === false ? 0 : moveRows('domains', sourceId, targetId),
      dnsCredentials: options.transferDnsCredentials === false ? 0 : moveRows('dns_credentials', sourceId, targetId),
      apiTokens: options.transferApiTokens === false ? 0 : moveRows('api_tokens', sourceId, targetId),
      inboundMailboxes: inboundCounts.mailboxes,
      inboundMessages: inboundCounts.messages,
      sendEvents: options.transferSendEvents === false ? 0 : moveRows('send_events', sourceId, targetId),
      smtpCredential: 0
    };
    if (options.transferSmtpCredential !== false && preview.counts.smtpCredential > 0) {
      counts.smtpCredential = moveRows('smtp_credentials', sourceId, targetId);
    }
    if (options.disableSource !== false) {
      requireDb()
        .prepare("UPDATE users SET status = 'disabled', updated_at = ? WHERE id = ?")
        .run(now(), sourceId);
    }
    logAudit({
      actorUserId,
      action: 'admin.user_merge',
      targetType: 'user',
      targetId: String(targetId),
      targetUserId: targetId,
      summary: {
        sourceUserId: sourceId,
        sourceUsername: preview.sourceUser.username,
        targetUserId: targetId,
        targetUsername: preview.targetUser.username,
        counts,
        warnings: preview.warnings
      }
    });
    return {
      sourceUser: getUser(sourceId),
      targetUser: getUser(targetId),
      counts,
      warnings: preview.warnings
    };
  });
}

export function getUser(id, { includeHash = false } = {}) {
  const row = requireDb().prepare('SELECT * FROM users WHERE id = ?').get(id);
  return includeHash ? privateUser(row) : publicUser(row);
}

export function getUserByLogin(login, { includeHash = false } = {}) {
  const value = String(login || '').trim().toLowerCase();
  if (!value) return null;
  const row = requireDb()
    .prepare('SELECT * FROM users WHERE lower(username) = ? OR lower(email) = ?')
    .get(value, value);
  return includeHash ? privateUser(row) : publicUser(row);
}

export function updateUser(id, patch) {
  const current = getUser(id, { includeHash: true });
  if (!current) return null;
  const passwordChanged = String(patch.password || '').length > 0;
  if (passwordChanged && String(patch.password).length < 8) throw new Error('密码至少需要 8 位。');
  const next = {
    role: patch.role === 'admin' ? 'admin' : current.role,
    status: patch.status === undefined ? current.status : normalizeUserStatus(patch.status),
    passwordHash: passwordChanged ? hashPassword(patch.password) : current.passwordHash,
    updatedAt: now()
  };
  requireDb()
    .prepare('UPDATE users SET role = ?, status = ?, password_hash = ?, updated_at = ? WHERE id = ?')
    .run(next.role, next.status, next.passwordHash, next.updatedAt, id);
  if (passwordChanged) invalidateAccountTokens(id, 'password_reset');
  return getUser(id);
}

export function updateUserStatus(id, status) {
  const nextStatus = normalizeUserStatus(status);
  if (!getUser(id)) return null;
  requireDb()
    .prepare('UPDATE users SET status = ?, updated_at = ? WHERE id = ?')
    .run(nextStatus, now(), id);
  return getUser(id);
}

export function approveUser(id) {
  return updateUserStatus(id, 'active');
}

export function markUserEmailVerified(id) {
  const user = getUser(id);
  if (!user) return null;
  if (user.status !== 'pending_email') return user;
  return updateUserStatus(id, 'pending_review');
}

export function getAdminUser() {
  const row = requireDb()
    .prepare("SELECT * FROM users WHERE role = 'admin' AND status = 'active' ORDER BY id LIMIT 1")
    .get();
  return publicUser(row);
}

export function listDomains(userId) {
  return requireDb()
    .prepare('SELECT * FROM domains WHERE user_id = ? ORDER BY created_at DESC')
    .all(userId)
    .map(publicDomainRow);
}

export function listDomainsForDnsAutoCheck() {
  return requireDb()
    .prepare('SELECT * FROM domains ORDER BY updated_at ASC')
    .all()
    .map(publicDomainRow);
}

export function getDomain(id, { userId, includePrivate = false } = {}) {
  const row = requireDb()
    .prepare('SELECT * FROM domains WHERE id = ? AND (? IS NULL OR user_id = ?)')
    .get(id, userId ?? null, userId ?? null);
  return includePrivate ? privateDomainRow(row) : publicDomainRow(row);
}

export function getDomainByName(domain, { userId, includePrivate = false } = {}) {
  const row = requireDb()
    .prepare('SELECT * FROM domains WHERE domain = ? AND (? IS NULL OR user_id = ?)')
    .get(String(domain || '').toLowerCase(), userId ?? null, userId ?? null);
  return includePrivate ? privateDomainRow(row) : publicDomainRow(row);
}

export function createDomain(userId, domain) {
  const createdAt = now();
  const result = requireDb()
    .prepare(`
      INSERT INTO domains (
        user_id, dns_credential_id, smtp_relay_id, domain, selector, verification_token,
        dkim_public, dkim_private, sender_host, sending_ip, spf_extra,
        dmarc_policy, dmarc_rua, status_json, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '{}', ?, ?)
    `)
    .run(
      userId,
      domain.dnsCredentialId || null,
      domain.smtpRelayId || null,
      domain.domain,
      domain.selector,
      domain.verificationToken,
      domain.dkimPublic,
      domain.dkimPrivate,
      domain.senderHost,
      domain.sendingIp,
      domain.spfExtra,
      domain.dmarcPolicy,
      domain.dmarcRua,
      createdAt,
      createdAt
    );
  return getDomain(result.lastInsertRowid, { userId });
}

export function createInboundMailbox(userId, mailbox = {}) {
  const address = normalizeInboundAddress(mailbox.address);
  if (!address) throw new Error('收信邮箱格式不正确。');
  const [localPart, domainName] = address.split('@');
  const domain = getDomainByName(domainName, { userId });
  if (!domain) throw new Error('收信域名不存在。');
  const password = String(mailbox.password || '');
  const passwordHash = password ? hashPassword(password) : '';
  const passwordSecret = password ? encryptSecret(password) : '';
  const aliases = normalizeMailboxAliases(mailbox.aliases, domain.domain, localPart);
  const forwardTo = normalizeRecipientList(mailbox.forwardTo);
  const keepForwarded = boolString(mailbox.keepForwarded ?? true);
  const quotaMb = normalizeQuotaMb(mailbox.quotaMb);
  const expiresAt = normalizeInboundMailboxExpiresAt(mailbox.expiresAt);
  const createdAt = now();
  const result = requireDb()
    .prepare(`
      INSERT INTO inbound_mailboxes (
        user_id, domain_id, address, local_part, display_name, password_hash, password_secret,
        aliases_json, forward_to_json, keep_forwarded, quota_mb, status, expires_at, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)
    `)
    .run(
      userId,
      domain.id,
      address,
      localPart,
      String(mailbox.displayName || '').trim(),
      passwordHash,
      passwordSecret,
      JSON.stringify(aliases),
      JSON.stringify(forwardTo),
      keepForwarded,
      quotaMb,
      expiresAt,
      createdAt,
      createdAt
    );
  return getInboundMailbox(result.lastInsertRowid, userId);
}

export function updateInboundMailbox(userId, id, patch = {}) {
  const current = getInboundMailbox(id, userId, { includeSecret: true });
  if (!current) return null;
  const password = Object.hasOwn(patch, 'password') ? String(patch.password || '') : null;
  const next = {
    displayName: patch.displayName === undefined ? current.displayName : String(patch.displayName || '').trim(),
    passwordHash: password ? hashPassword(password) : current.passwordHash,
    passwordSecret: password ? encryptSecret(password) : current.passwordSecret,
    aliases: Object.hasOwn(patch, 'aliases')
      ? normalizeMailboxAliases(patch.aliases, current.domain, current.localPart)
      : current.aliases,
    forwardTo: Object.hasOwn(patch, 'forwardTo') ? normalizeRecipientList(patch.forwardTo) : current.forwardTo,
    keepForwarded: Object.hasOwn(patch, 'keepForwarded') ? Boolean(patch.keepForwarded) : current.keepForwarded,
    quotaMb: Object.hasOwn(patch, 'quotaMb') ? normalizeQuotaMb(patch.quotaMb) : current.quotaMb,
    expiresAt: Object.hasOwn(patch, 'expiresAt') ? normalizeInboundMailboxExpiresAt(patch.expiresAt) : current.expiresAt,
    status: patch.status === undefined ? current.status : normalizeInboundMailboxStatus(patch.status),
    updatedAt: now()
  };
  if (!next.passwordHash) next.passwordSecret = '';
  requireDb()
    .prepare(`
      UPDATE inbound_mailboxes
      SET display_name = ?, password_hash = ?, password_secret = ?, aliases_json = ?, forward_to_json = ?,
          keep_forwarded = ?, quota_mb = ?, expires_at = ?, status = ?, updated_at = ?
      WHERE id = ? AND user_id = ? AND deleted_at IS NULL
    `)
    .run(
      next.displayName,
      next.passwordHash || '',
      next.passwordSecret || '',
      JSON.stringify(next.aliases),
      JSON.stringify(next.forwardTo),
      boolString(next.keepForwarded),
      next.quotaMb,
      next.expiresAt,
      next.status,
      next.updatedAt,
      Number(id),
      userId
    );
  return getInboundMailbox(id, userId);
}

export function listInboundMailboxes(userId) {
  return requireDb()
    .prepare(`
      SELECT
        m.*,
        d.domain,
        COUNT(msg.id) AS message_count,
        COALESCE(SUM(CASE WHEN msg.read_state = 'false' THEN 1 ELSE 0 END), 0) AS unread_count,
        MAX(msg.received_at) AS last_message_at
      FROM inbound_mailboxes m
      JOIN domains d ON d.id = m.domain_id
      LEFT JOIN inbound_messages msg ON msg.mailbox_id = m.id AND msg.deleted_at IS NULL
      WHERE m.user_id = ? AND m.deleted_at IS NULL
      GROUP BY m.id
      ORDER BY COALESCE(last_message_at, m.created_at) DESC, m.id DESC
    `)
    .all(userId)
    .map(publicInboundMailbox);
}

export function getInboundMailbox(id, userId, { includeHash = false, includeSecret = false } = {}) {
  const row = requireDb()
    .prepare(`
      SELECT
        m.*,
        d.domain,
        COUNT(msg.id) AS message_count,
        COALESCE(SUM(CASE WHEN msg.read_state = 'false' THEN 1 ELSE 0 END), 0) AS unread_count,
        MAX(msg.received_at) AS last_message_at
      FROM inbound_mailboxes m
      JOIN domains d ON d.id = m.domain_id
      LEFT JOIN inbound_messages msg ON msg.mailbox_id = m.id AND msg.deleted_at IS NULL
      WHERE m.id = ? AND m.user_id = ? AND m.deleted_at IS NULL
      GROUP BY m.id
    `)
    .get(Number(id), userId);
  return publicInboundMailbox(row, { includeHash, includeSecret });
}

export function getInboundMailboxByAddress(address, { includeHash = false, includeSecret = false } = {}) {
  const cleanAddress = normalizeInboundAddress(address);
  if (!cleanAddress) return null;
  const row = requireDb()
    .prepare(`
      SELECT m.*, d.domain, 0 AS message_count, 0 AS unread_count, NULL AS last_message_at
      FROM inbound_mailboxes m
      JOIN domains d ON d.id = m.domain_id
      JOIN users u ON u.id = m.user_id
      WHERE m.address = ?
        AND m.status = 'active'
        AND m.deleted_at IS NULL
        AND (m.expires_at IS NULL OR m.expires_at = '' OR m.expires_at > ?)
        AND u.status = 'active'
      LIMIT 1
    `)
    .get(cleanAddress, now());
  return publicInboundMailbox(row, { includeHash, includeSecret });
}

export function verifyInboundMailboxCredential(username, password) {
  const mailboxAddress = normalizeInboundAddress(username);
  if (!mailboxAddress) return null;
  const row = requireDb()
    .prepare(`
      SELECT
        m.*,
        d.domain,
        0 AS message_count,
        0 AS unread_count,
        NULL AS last_message_at,
        u.id AS auth_user_id,
        u.username AS auth_username,
        u.email,
        u.role,
        u.status AS user_status
      FROM inbound_mailboxes m
      JOIN domains d ON d.id = m.domain_id
      JOIN users u ON u.id = m.user_id
      WHERE m.address = ?
        AND m.status = 'active'
        AND m.deleted_at IS NULL
        AND (m.expires_at IS NULL OR m.expires_at = '' OR m.expires_at > ?)
      LIMIT 1
    `)
    .get(mailboxAddress, now());
  if (!row?.password_hash || row.user_status !== 'active' || !verifyPassword(password, row.password_hash)) return null;
  return {
    user: {
      id: row.auth_user_id,
      username: row.auth_username,
      email: row.email,
      role: row.role,
      status: row.user_status
    },
    mailbox: publicInboundMailbox(row)
  };
}

export function resolveInboundRecipient(address) {
  const recipient = normalizeInboundAddress(address);
  if (!recipient) return null;
  const exactMailbox = getInboundMailboxByAddress(recipient);
  if (exactMailbox) return inboundRouteForMailbox(recipient, exactMailbox);

  const aliasMailbox = getInboundMailboxByAliasAddress(recipient);
  if (aliasMailbox) return inboundRouteForMailbox(recipient, aliasMailbox, { alias: true });

  const [, domainName] = recipient.split('@');
  const domain = getDomainByName(domainName);
  const catchAllAddress = normalizeCatchAllAddress(domain?.catchAllAddress);
  if (!domain || !catchAllAddress) return null;
  if (catchAllAddress === '/dev/null') {
    return {
      recipient,
      domainId: domain.id,
      userId: domain.userId,
      mailbox: null,
      forwardTo: [],
      keepForwarded: false,
      drop: true,
      catchAll: true,
      alias: false
    };
  }

  const catchAllMailbox = getInboundMailboxByAddress(catchAllAddress);
  if (catchAllMailbox) return inboundRouteForMailbox(recipient, catchAllMailbox, { catchAll: true });

  const forwardTo = normalizeRecipientList(catchAllAddress);
  if (!forwardTo.length) return null;
  return {
    recipient,
    domainId: domain.id,
    userId: domain.userId,
    mailbox: null,
    forwardTo,
    keepForwarded: false,
    drop: false,
    catchAll: true,
    alias: false
  };
}

export function createInboundMessage(mailbox, message = {}) {
  if (!mailbox?.id || !mailbox?.userId || !mailbox?.domainId) throw new Error('收信邮箱不存在。');
  const receivedAt = message.receivedAt || now();
  const folder = normalizeInboundFolder(message.folder) || 'INBOX';
  const textBody = String(message.textBody || '');
  const htmlBody = String(message.htmlBody || '');
  const rawMessage = String(message.rawMessage || '');
  if (!isStandardInboundFolder(folder)) createInboundFolder(mailbox, folder);
  const result = requireDb()
    .prepare(`
      INSERT INTO inbound_messages (
        mailbox_id, user_id, domain_id, folder, sender, recipients_json, subject, message_id,
        raw_message, text_body, html_body, preview, read_state, received_at, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'false', ?, ?, ?)
    `)
    .run(
      mailbox.id,
      mailbox.userId,
      mailbox.domainId,
      folder,
      normalizeEmail(message.sender) || String(message.sender || '').trim(),
      JSON.stringify(normalizeRecipientList(message.recipients)),
      String(message.subject || '').trim() || '(no subject)',
      String(message.messageId || '').trim(),
      rawMessage,
      textBody,
      htmlBody,
      inboundPreview(textBody || htmlToText(htmlBody) || rawMessage),
      receivedAt,
      receivedAt,
      receivedAt
    );
  return getInboundMessage(mailbox.userId, result.lastInsertRowid);
}

export function listInboundMessages(userId, { mailboxId = null, folder = 'INBOX' } = {}) {
  const where = ['msg.user_id = ?', 'msg.deleted_at IS NULL'];
  const params = [userId];
  if (mailboxId) {
    where.push('msg.mailbox_id = ?');
    params.push(Number(mailboxId));
  }
  if (folder !== null) {
    where.push('msg.folder = ?');
    params.push(normalizeInboundFolder(folder) || 'INBOX');
  }
  return requireDb()
    .prepare(`
      SELECT msg.*, m.address AS mailbox_address, d.domain
      FROM inbound_messages msg
      JOIN inbound_mailboxes m ON m.id = msg.mailbox_id
      JOIN domains d ON d.id = msg.domain_id
      WHERE ${where.join(' AND ')}
      ORDER BY msg.received_at DESC, msg.id DESC
    `)
    .all(...params)
    .map((row) => publicInboundMessage(row));
}

export function getInboundMessage(userId, id) {
  const row = requireDb()
    .prepare(`
      SELECT msg.*, m.address AS mailbox_address, d.domain
      FROM inbound_messages msg
      JOIN inbound_mailboxes m ON m.id = msg.mailbox_id
      JOIN domains d ON d.id = msg.domain_id
      WHERE msg.id = ? AND msg.user_id = ? AND msg.deleted_at IS NULL
    `)
    .get(Number(id), userId);
  return publicInboundMessage(row, { includeBody: true });
}

export function listInboundFolders(mailbox) {
  if (!mailbox?.id || !mailbox?.userId) return [...STANDARD_INBOUND_FOLDERS];
  const custom = requireDb()
    .prepare(`
      SELECT name
      FROM inbound_folders
      WHERE mailbox_id = ? AND user_id = ? AND deleted_at IS NULL
      ORDER BY name COLLATE NOCASE
    `)
    .all(Number(mailbox.id), mailbox.userId)
    .map((row) => row.name)
    .filter((name) => !isStandardInboundFolder(name));
  return [...STANDARD_INBOUND_FOLDERS, ...custom];
}

export function createInboundFolder(mailbox, folder) {
  if (!mailbox?.id || !mailbox?.userId) throw new Error('收信邮箱不存在。');
  const name = normalizeInboundFolder(folder);
  if (!name) throw new Error('IMAP 文件夹名称不正确。');
  if (isStandardInboundFolder(name)) return { name, standard: true };
  const createdAt = now();
  requireDb()
    .prepare(`
      INSERT OR IGNORE INTO inbound_folders (mailbox_id, user_id, name, subscribed, created_at, updated_at)
      VALUES (?, ?, ?, 'true', ?, ?)
    `)
    .run(Number(mailbox.id), mailbox.userId, name, createdAt, createdAt);
  return { name, standard: false };
}

export function inboundFolderExists(mailbox, folder) {
  if (!mailbox?.id || !mailbox?.userId) return false;
  const name = normalizeInboundFolder(folder);
  if (!name) return false;
  if (isStandardInboundFolder(name)) return true;
  return Boolean(requireDb()
    .prepare(`
      SELECT id
      FROM inbound_folders
      WHERE mailbox_id = ? AND user_id = ? AND name = ? AND deleted_at IS NULL
      LIMIT 1
    `)
    .get(Number(mailbox.id), mailbox.userId, name));
}

export function listInboundMailboxProtocolMessages(mailbox, { folder = 'INBOX' } = {}) {
  if (!mailbox?.id || !mailbox?.userId) return [];
  const selectedFolder = normalizeInboundFolder(folder) || 'INBOX';
  return requireDb()
    .prepare(`
      SELECT msg.*, m.address AS mailbox_address, d.domain
      FROM inbound_messages msg
      JOIN inbound_mailboxes m ON m.id = msg.mailbox_id
      JOIN domains d ON d.id = msg.domain_id
      WHERE msg.mailbox_id = ? AND msg.user_id = ? AND msg.folder = ? AND msg.deleted_at IS NULL
      ORDER BY msg.id ASC
    `)
    .all(Number(mailbox.id), mailbox.userId, selectedFolder)
    .map((row) => publicInboundMessage(row, { includeBody: true }));
}

export function markInboundMessageRead(userId, id, read = true) {
  const updatedAt = now();
  const result = requireDb()
    .prepare('UPDATE inbound_messages SET read_state = ?, updated_at = ? WHERE id = ? AND user_id = ? AND deleted_at IS NULL')
    .run(read ? 'true' : 'false', updatedAt, Number(id), userId);
  if (!result.changes) return null;
  return getInboundMessage(userId, id);
}

export function softDeleteInboundMessages(userId, mailboxId, ids, { folder = null } = {}) {
  const cleanIds = [...new Set((Array.isArray(ids) ? ids : [ids])
    .map((id) => Number(id))
    .filter((id) => Number.isInteger(id) && id > 0))];
  if (!cleanIds.length) return 0;
  const folderClause = folder === null ? '' : 'AND folder = ?';
  const placeholders = cleanIds.map(() => '?').join(', ');
  const updatedAt = now();
  const params = folder === null
    ? [updatedAt, updatedAt, userId, Number(mailboxId), ...cleanIds]
    : [updatedAt, updatedAt, userId, Number(mailboxId), normalizeInboundFolder(folder) || 'INBOX', ...cleanIds];
  const result = requireDb()
    .prepare(`
      UPDATE inbound_messages
      SET deleted_at = ?, updated_at = ?
      WHERE user_id = ? AND mailbox_id = ? AND deleted_at IS NULL ${folderClause} AND id IN (${placeholders})
    `)
    .run(...params);
  return result.changes;
}

export function updateDomain(id, userId, patch) {
  const current = getDomain(id, { userId, includePrivate: true });
  if (!current) return null;
  const next = {
    selector: patch.selector ?? current.selector,
    dnsCredentialId: patch.dnsCredentialId === undefined ? current.dnsCredentialId : (patch.dnsCredentialId || null),
    smtpRelayId: patch.smtpRelayId === undefined ? current.smtpRelayId : (patch.smtpRelayId || null),
    senderHost: patch.senderHost ?? current.senderHost,
    sendingIp: patch.sendingIp ?? current.sendingIp,
    spfExtra: patch.spfExtra ?? current.spfExtra,
    dmarcPolicy: patch.dmarcPolicy ?? current.dmarcPolicy,
    dmarcRua: patch.dmarcRua ?? current.dmarcRua,
    catchAllAddress: patch.catchAllAddress === undefined
      ? current.catchAllAddress
      : normalizeCatchAllAddress(patch.catchAllAddress),
    updatedAt: now()
  };
  requireDb()
    .prepare(`
      UPDATE domains
      SET selector = ?, dns_credential_id = ?, smtp_relay_id = ?, sender_host = ?, sending_ip = ?, spf_extra = ?,
          dmarc_policy = ?, dmarc_rua = ?, catch_all_address = ?, updated_at = ?
      WHERE id = ? AND user_id = ?
    `)
    .run(
      next.selector,
      next.dnsCredentialId,
      next.smtpRelayId,
      next.senderHost,
      next.sendingIp,
      next.spfExtra,
      next.dmarcPolicy,
      next.dmarcRua,
      next.catchAllAddress,
      next.updatedAt,
      id,
      userId
    );
  return getDomain(id, { userId });
}

export function updateDkim(id, userId, keys, selector) {
  requireDb()
    .prepare('UPDATE domains SET selector = ?, dkim_public = ?, dkim_private = ?, updated_at = ? WHERE id = ? AND user_id = ?')
    .run(selector, keys.publicKey, keys.privateKey, now(), id, userId);
  return getDomain(id, { userId });
}

export function saveDomainStatus(id, userId, status) {
  requireDb()
    .prepare('UPDATE domains SET status_json = ?, updated_at = ? WHERE id = ? AND user_id = ?')
    .run(JSON.stringify(status), now(), id, userId);
}

export function deleteDomain(id, userId) {
  const result = requireDb().prepare('DELETE FROM domains WHERE id = ? AND user_id = ?').run(id, userId);
  return result.changes > 0;
}

export function logAudit({ actorUserId, action, targetType, targetId = '', targetUserId = null, summary = {} }) {
  const result = requireDb()
    .prepare(`
      INSERT INTO audit_logs (
        actor_user_id, action, target_type, target_id, target_user_id, summary_json, created_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `)
    .run(
      actorUserId ?? null,
      String(action || ''),
      String(targetType || ''),
      String(targetId ?? ''),
      targetUserId ?? null,
      JSON.stringify(sanitizeAuditSummary(summary)),
      now()
    );
  return result.lastInsertRowid;
}

export function listAuditLogs(filters = {}) {
  const where = [];
  const params = [];
  addAuditFilter(where, params, 'actor_user_id', filters.actorUserId);
  addAuditFilter(where, params, 'target_user_id', filters.targetUserId);
  addAuditFilter(where, params, 'action', filters.action);
  addAuditDateFilter(where, params, 'created_at', '>=', filters.from);
  addAuditDateFilter(where, params, 'created_at', '<=', filters.to);
  const query = `
    SELECT *
    FROM audit_logs
    ${where.length ? `WHERE ${where.join(' AND ')}` : ''}
    ORDER BY created_at DESC, id DESC
  `;
  return requireDb().prepare(query).all(...params).map(publicAuditLog);
}

export function createSendEvent(event) {
  const queueId = normalizeQueueId(event.queueId || extractQueueIdFromText(event.detail));
  const recipients = Array.isArray(event.recipients) ? event.recipients : [];
  const status = event.status || 'submitting';
  const trackingTokenHash = event.trackingToken ? hashTrackingToken(event.trackingToken) : null;
  const result = requireDb()
    .prepare(`
      INSERT INTO send_events (
        user_id, domain_id, smtp_relay_id, sender, recipients, subject, status, detail, queue_id,
        delivery_log_json, delivery_attempts_json, delivered_at,
        tracking_token_hash, tracking_opens, tracking_clicks, created_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
    .run(
      event.userId ?? null,
      event.domainId ?? null,
      event.smtpRelayId ?? null,
      event.sender,
      JSON.stringify(recipients),
      event.subject,
      status,
      event.detail ?? '',
      queueId,
      JSON.stringify(Array.isArray(event.deliveryLog) ? event.deliveryLog : []),
      JSON.stringify(Array.isArray(event.deliveryAttempts) ? event.deliveryAttempts : []),
      event.deliveredAt ?? null,
      trackingTokenHash,
      boolString(event.trackingOpens),
      boolString(event.trackingClicks),
      now()
    );
  const id = result.lastInsertRowid;
  if (isTerminalWebhookStatus(status)) {
    try {
      enqueueWebhookDeliveries({
        id,
        userId: event.userId,
        domainId: event.domainId ?? null,
        domain: event.domain,
        status,
        sender: event.sender,
        recipients,
        subject: event.subject,
        detail: event.detail ?? '',
        queueId,
        deliveredAt: event.deliveredAt ?? null
      });
    } catch (error) {
      console.error('webhook enqueue after logSendEvent failed', error);
    }
  }
  return id;
}

export function logSendEvent(event) {
  return createSendEvent(event);
}

export function finalizeSendEvent(id, userId, patch = {}) {
  const row = requireDb().prepare('SELECT * FROM send_events WHERE id = ? AND user_id = ?').get(Number(id), userId);
  if (!row) return null;
  const recipients = safeJson(row.recipients, []);
  const status = patch.status || row.status;
  const detail = patch.detail ?? row.detail;
  const queueId = normalizeQueueId(patch.queueId || extractQueueIdFromText(detail) || row.queue_id);
  const deliveryLog = Array.isArray(patch.deliveryLog) ? patch.deliveryLog : safeJson(row.delivery_log_json, []);
  const deliveryAttempts = Array.isArray(patch.deliveryAttempts)
    ? patch.deliveryAttempts
    : safeJson(row.delivery_attempts_json, []);
  const deliveredAt = patch.deliveredAt === undefined ? row.delivered_at : patch.deliveredAt;
  const smtpRelayId = patch.smtpRelayId === undefined ? row.smtp_relay_id : patch.smtpRelayId;
  const trackingOpens = patch.trackingOpens === undefined ? row.tracking_opens : boolString(patch.trackingOpens);
  const trackingClicks = patch.trackingClicks === undefined ? row.tracking_clicks : boolString(patch.trackingClicks);
  requireDb()
    .prepare(`
      UPDATE send_events
      SET smtp_relay_id = ?, status = ?, detail = ?, queue_id = ?,
          delivery_log_json = ?, delivery_attempts_json = ?, delivered_at = ?,
          tracking_opens = ?, tracking_clicks = ?
      WHERE id = ? AND user_id = ?
    `)
    .run(
      smtpRelayId ?? null,
      status,
      detail,
      queueId,
      JSON.stringify(deliveryLog),
      JSON.stringify(deliveryAttempts),
      deliveredAt ?? null,
      trackingOpens,
      trackingClicks,
      row.id,
      userId
    );
  if (isTerminalWebhookStatus(status) && status !== row.status) {
    try {
      enqueueWebhookDeliveries({
        id: row.id,
        userId: row.user_id,
        domainId: row.domain_id,
        status,
        sender: row.sender,
        recipients,
        subject: row.subject,
        detail,
        queueId,
        deliveredAt
      });
    } catch (error) {
      console.error('webhook enqueue after finalizeSendEvent failed', error);
    }
  }
  return getSendEvent(userId, row.id);
}

export function updateSendEventDelivery(queueId, attempt) {
  const cleanQueueId = normalizeQueueId(queueId || attempt?.queueId);
  if (!cleanQueueId) return false;
  const row = requireDb().prepare('SELECT * FROM send_events WHERE queue_id = ? ORDER BY id DESC LIMIT 1').get(cleanQueueId);
  if (!row) return false;
  const normalizedAttempt = normalizeDeliveryAttempt(attempt, cleanQueueId);
  const attempts = safeJson(row.delivery_attempts_json, []);
  if (attempts.some((item) => deliveryAttemptKey(item) === deliveryAttemptKey(normalizedAttempt))) return true;
  const nextAttempts = [...attempts, normalizedAttempt];
  const recipients = safeJson(row.recipients, []);
  const previousStatus = row.status;
  const nextStatus = deliveryStatusForEvent(recipients, nextAttempts, row.status);
  const deliveredAt = nextStatus === 'sent' ? normalizedAttempt.at : row.delivered_at;
  const detail = deliveryAttemptDetail(normalizedAttempt);
  requireDb()
    .prepare(`
      UPDATE send_events
      SET status = ?, detail = ?, delivery_attempts_json = ?, delivered_at = ?
      WHERE id = ?
    `)
    .run(nextStatus, detail, JSON.stringify(nextAttempts), deliveredAt, row.id);
  if (isTerminalWebhookStatus(nextStatus) && nextStatus !== previousStatus) {
    try {
      enqueueWebhookDeliveries({
        id: row.id,
        userId: row.user_id,
        domainId: row.domain_id,
        status: nextStatus,
        sender: row.sender,
        recipients,
        subject: row.subject,
        detail,
        queueId: cleanQueueId,
        deliveredAt
      });
    } catch (error) {
      console.error('webhook enqueue after updateSendEventDelivery failed', error);
    }
  }
  return true;
}

export function listSendEvents(userId, limit = 30) {
  const rows = requireDb()
    .prepare(`
      SELECT e.*, d.domain
      FROM send_events e
      LEFT JOIN domains d ON d.id = e.domain_id
      WHERE e.user_id = ?
      ORDER BY e.created_at DESC
      LIMIT ?
    `)
    .all(userId, limit);
  const trackingAggregates = listTrackingAggregates(rows.map((row) => row.id));
  return rows.map((row) => {
      const event = publicSendEvent(row);
      return {
        ...event,
        tracking: {
          ...event.tracking,
          summary: trackingAggregates.get(event.id)?.summary || emptyTrackingSummary()
        }
      };
    });
}

export function getSendEvent(userId, eventId, { trackingSecret = '' } = {}) {
  const event = publicSendEvent(
    requireDb()
      .prepare(`
        SELECT e.*, d.domain
        FROM send_events e
        LEFT JOIN domains d ON d.id = e.domain_id
        WHERE e.user_id = ? AND e.id = ?
      `)
      .get(userId, Number(eventId))
  );
  if (!event) return null;
  const trackingAggregate = listTrackingAggregates([event.id]).get(event.id) || {
    eventCount: 0,
    summary: emptyTrackingSummary()
  };
  const trackingEvents = listTrackingEventsForSendEvent(event.id, 500);
  const linkCount = countTrackingLinksForSendEvent(event.id);
  const trackingLinks = listTrackingLinksForSendEvent(event.id, trackingSecret, 200);
  return {
    ...event,
    tracking: {
      ...event.tracking,
      summary: trackingAggregate.summary,
      events: trackingEvents,
      eventCount: trackingAggregate.eventCount,
      eventsTruncated: trackingAggregate.eventCount > trackingEvents.length,
      links: trackingLinks,
      linkCount,
      linksTruncated: linkCount > trackingLinks.length
    },
    webhookDeliveries: listWebhookDeliveries(userId, {
      sendEventId: event.id,
      limit: 50
    })
  };
}

export function findSendEventByTrackingToken(token) {
  if (!token) return null;
  return publicSendEvent(
    requireDb()
      .prepare(`
        SELECT e.*, d.domain
        FROM send_events e
        LEFT JOIN domains d ON d.id = e.domain_id
        WHERE e.tracking_token_hash = ?
      `)
      .get(hashTrackingToken(token))
  );
}

export function createTrackingLink(userId, sendEventId, link) {
  const event = requireDb()
    .prepare('SELECT id FROM send_events WHERE id = ? AND user_id = ?')
    .get(Number(sendEventId), userId);
  if (!event) throw new Error('Send event not found.');
  if (!link?.token) throw new Error('Tracking link token is required.');
  const result = requireDb()
    .prepare(`
      INSERT INTO tracking_links (
        send_event_id, token_hash, target_ciphertext, target_fingerprint, target_origin, created_at
      ) VALUES (?, ?, ?, ?, ?, ?)
    `)
    .run(
      event.id,
      hashTrackingToken(link.token),
      String(link.targetCiphertext || ''),
      String(link.targetFingerprint || ''),
      String(link.targetOrigin || ''),
      now()
    );
  return result.lastInsertRowid;
}

export function findTrackingLinkByToken(token) {
  if (!token) return null;
  const row = requireDb()
    .prepare(`
      SELECT l.*, e.user_id, e.domain_id, e.sender, e.recipients, e.subject,
             e.status, e.tracking_clicks, d.domain
      FROM tracking_links l
      JOIN send_events e ON e.id = l.send_event_id
      LEFT JOIN domains d ON d.id = e.domain_id
      WHERE l.token_hash = ?
    `)
    .get(hashTrackingToken(token));
  return publicTrackingLink(row);
}

export function recordTrackingEvent(input) {
  const database = requireDb();
  const sendEventId = Number(input.sendEventId);
  const eventType = String(input.eventType || '').toLowerCase();
  const source = normalizeTrackingSource(input.source);
  const occurredAt = normalizeIsoDate(input.occurredAt);
  const trackingLinkId = input.trackingLinkId == null ? null : Number(input.trackingLinkId);
  const maxPerDay = Math.max(1, Math.min(1000, Number(input.maxPerDay) || 1000));
  if (!['open', 'click'].includes(eventType)) throw new Error('Invalid tracking event type.');
  const sendEvent = database.prepare('SELECT * FROM send_events WHERE id = ?').get(sendEventId);
  if (!sendEvent) return { recorded: false, notFound: true, firstQualifying: false };
  if (eventType === 'open' && sendEvent.tracking_opens !== 'true') {
    return { recorded: false, disabled: true, firstQualifying: false };
  }
  if (eventType === 'click') {
    if (sendEvent.tracking_clicks !== 'true') return { recorded: false, disabled: true, firstQualifying: false };
    const link = database
      .prepare('SELECT id FROM tracking_links WHERE id = ? AND send_event_id = ?')
      .get(trackingLinkId, sendEventId);
    if (!link) return { recorded: false, notFound: true, firstQualifying: false };
  }

  const dayStart = `${occurredAt.slice(0, 10)}T00:00:00.000Z`;
  const dayEndDate = new Date(dayStart);
  dayEndDate.setUTCDate(dayEndDate.getUTCDate() + 1);
  const dayEnd = dayEndDate.toISOString();
  database.exec('BEGIN IMMEDIATE');
  try {
    const existing = database.prepare('SELECT id FROM tracking_events WHERE replay_key = ?').get(String(input.replayKey || ''));
    if (existing) {
      database.exec('COMMIT');
      return { recorded: false, duplicate: true, firstQualifying: false };
    }
    const dailyCount = database
      .prepare(`
        SELECT COUNT(*) AS total
        FROM tracking_events
        WHERE send_event_id = ? AND occurred_at >= ? AND occurred_at < ?
      `)
      .get(sendEventId, dayStart, dayEnd)?.total || 0;
    if (dailyCount >= maxPerDay) {
      database.exec('COMMIT');
      return { recorded: false, capped: true, firstQualifying: false };
    }
    const qualifies = isQualifyingTrackingEvent(eventType, source);
    const qualifyingBefore = qualifies
      ? database
          .prepare(`
            SELECT COUNT(*) AS total
            FROM tracking_events
            WHERE send_event_id = ? AND event_type = ?
              AND ${eventType === 'click' ? "source = 'direct'" : "source != 'scanner'"}
          `)
          .get(sendEventId, eventType)?.total || 0
      : 0;
    const result = database
      .prepare(`
        INSERT INTO tracking_events (
          send_event_id, tracking_link_id, event_type, source, occurred_at,
          user_agent, ip_hash, replay_key, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `)
      .run(
        sendEventId,
        trackingLinkId,
        eventType,
        source,
        occurredAt,
        String(input.userAgent || '').slice(0, 500),
        String(input.ipHash || ''),
        String(input.replayKey || ''),
        now()
      );
    const row = database
      .prepare(`
        SELECT te.*, tl.target_origin
        FROM tracking_events te
        LEFT JOIN tracking_links tl ON tl.id = te.tracking_link_id
        WHERE te.id = ?
      `)
      .get(result.lastInsertRowid);
    const firstQualifying = qualifies && qualifyingBefore === 0;
    if (firstQualifying) {
      enqueueWebhookDeliveries(
        {
          id: sendEvent.id,
          userId: sendEvent.user_id,
          domainId: sendEvent.domain_id,
          status: sendEvent.status,
          sender: sendEvent.sender,
          recipients: safeJson(sendEvent.recipients, []),
          subject: sendEvent.subject,
          detail: sendEvent.detail,
          queueId: sendEvent.queue_id,
          deliveredAt: sendEvent.delivered_at
        },
        {
          database,
          manageTransactions: false,
          eventType: eventType === 'open' ? 'opened' : 'clicked',
          engagement: {
            type: eventType,
            occurredAt,
            source,
            linkId: trackingLinkId,
            targetOrigin: row.target_origin || ''
          }
        }
      );
    }
    database.exec('COMMIT');
    return {
      recorded: true,
      firstQualifying,
      event: publicTrackingEvent(row)
    };
  } catch (error) {
    try {
      database.exec('ROLLBACK');
    } catch {
      // ignore rollback errors when no transaction is active
    }
    if (/UNIQUE constraint failed: tracking_events\.replay_key/i.test(String(error?.message || ''))) {
      return { recorded: false, duplicate: true, firstQualifying: false };
    }
    throw error;
  }
}

export function pruneTrackingEvents({ days = 180, now: currentTime } = {}) {
  const retentionDays = Math.max(1, Number(days) || 180);
  const cutoff = new Date(currentTime || Date.now());
  if (Number.isNaN(cutoff.getTime())) throw new Error('Invalid tracking retention time.');
  cutoff.setUTCDate(cutoff.getUTCDate() - retentionDays);
  return Number(requireDb().prepare('DELETE FROM tracking_events WHERE occurred_at < ?').run(cutoff.toISOString()).changes || 0);
}

export function listWebhooks(userId, { domainId } = {}) {
  const params = [userId];
  let domainClause = '';
  if (domainId === null) {
    domainClause = ' AND domain_id IS NULL';
  } else if (domainId !== undefined) {
    domainClause = ' AND domain_id = ?';
    params.push(domainId);
  }
  return requireDb()
    .prepare(`
      SELECT *
      FROM webhooks
      WHERE user_id = ?${domainClause}
      ORDER BY created_at DESC, id DESC
    `)
    .all(...params)
    .map(publicWebhook);
}

export function getWebhook(id, userId) {
  const row = getWebhookRow(id, userId);
  return publicWebhook(row);
}

export function createWebhook(userId, { name, url, events, domainId = null, enabled = true } = {}) {
  const cleanName = String(name || '').trim();
  const cleanUrl = String(url || '').trim();
  if (!cleanName) throw new Error('Webhook 名称不能为空。');
  if (!cleanUrl) throw new Error('Webhook URL 不能为空。');
  const normalizedEvents = normalizeWebhookEvents(events);
  const resolvedDomainId = normalizeWebhookDomainId(userId, domainId);
  const secret = generateWebhookSecret();
  const createdAt = now();
  const result = requireDb()
    .prepare(`
      INSERT INTO webhooks (
        user_id, domain_id, name, url, secret_ciphertext, secret_prefix,
        events_json, enabled, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
    .run(
      userId,
      resolvedDomainId,
      cleanName,
      cleanUrl,
      encryptSecret(secret),
      secret.slice(0, 8),
      JSON.stringify(normalizedEvents),
      boolString(enabled),
      createdAt,
      createdAt
    );
  return {
    ...getWebhook(result.lastInsertRowid, userId),
    secret
  };
}

export function updateWebhook(userId, id, patch = {}) {
  const current = getWebhookRow(id, userId);
  if (!current) return null;
  const nextName = patch.name !== undefined ? String(patch.name || '').trim() : current.name;
  const nextUrl = patch.url !== undefined ? String(patch.url || '').trim() : current.url;
  if (!nextName) throw new Error('Webhook 名称不能为空。');
  if (!nextUrl) throw new Error('Webhook URL 不能为空。');
  const nextEvents = patch.events !== undefined
    ? normalizeWebhookEvents(patch.events)
    : parseWebhookEventsJson(current.events_json);
  const nextDomainId = patch.domainId !== undefined
    ? normalizeWebhookDomainId(userId, patch.domainId)
    : current.domain_id;
  const nextEnabled = patch.enabled !== undefined ? boolString(patch.enabled) : current.enabled;
  const updatedAt = now();
  requireDb()
    .prepare(`
      UPDATE webhooks
      SET domain_id = ?, name = ?, url = ?, events_json = ?, enabled = ?, updated_at = ?
      WHERE id = ? AND user_id = ?
    `)
    .run(nextDomainId, nextName, nextUrl, JSON.stringify(nextEvents), nextEnabled, updatedAt, id, userId);
  return getWebhook(id, userId);
}

export function rotateWebhookSecret(userId, id) {
  const current = getWebhookRow(id, userId);
  if (!current) return null;
  const secret = generateWebhookSecret();
  const updatedAt = now();
  requireDb()
    .prepare(`
      UPDATE webhooks
      SET secret_ciphertext = ?, secret_prefix = ?, updated_at = ?
      WHERE id = ? AND user_id = ?
    `)
    .run(encryptSecret(secret), secret.slice(0, 8), updatedAt, id, userId);
  return {
    ...getWebhook(id, userId),
    secret
  };
}

export function deleteWebhook(userId, id) {
  const result = requireDb()
    .prepare('DELETE FROM webhooks WHERE id = ? AND user_id = ?')
    .run(id, userId);
  return result.changes > 0;
}

/**
 * Enqueue pending webhook deliveries for a delivery or engagement event.
 * Idempotent on (webhook_id, send_event_id, event_type).
 */
export function enqueueWebhookDeliveries(sendEvent, options = {}) {
  if (!sendEvent?.userId) return [];
  const eventType = options.eventType || sendEvent.status;
  if (!options.eventType && !isTerminalWebhookStatus(sendEvent.status)) return [];

  const externalType = eventTypeForStatus(eventType);
  if (!externalType) return [];

  const domainId = sendEvent.domainId ?? null;
  const domainName = resolveSendEventDomainName(sendEvent);
  const recipients = Array.isArray(sendEvent.recipients)
    ? sendEvent.recipients
    : safeJson(sendEvent.recipients, []);
  const normalizedEvent = {
    id: sendEvent.id,
    userId: sendEvent.userId,
    domainId,
    domain: domainName,
    status: sendEvent.status,
    sender: sendEvent.sender || '',
    recipients,
    subject: sendEvent.subject || '',
    detail: sendEvent.detail || '',
    queueId: sendEvent.queueId || '',
    deliveredAt: sendEvent.deliveredAt ?? null
  };

  const accountWebhooks = listWebhookRowsForResolve(sendEvent.userId, null);
  const domainWebhooks = domainId == null
    ? []
    : listWebhookRowsForResolve(sendEvent.userId, domainId);
  const targets = resolveWebhooksForEvent({
    accountWebhooks,
    domainWebhooks,
    eventType
  });

  const created = [];
  const database = options.database || requireDb();
  const manageTransactions = options.manageTransactions !== false;
  for (const webhook of targets) {
    if (manageTransactions) database.exec('BEGIN');
    try {
      const existing = database
        .prepare(`
          SELECT id FROM webhook_deliveries
          WHERE webhook_id = ? AND send_event_id = ? AND event_type = ?
        `)
        .get(webhook.id, normalizedEvent.id, eventType);
      if (existing) {
        if (manageTransactions) database.exec('COMMIT');
        continue;
      }

      const createdAt = now();
      const insert = database
        .prepare(`
          INSERT INTO webhook_deliveries (
            webhook_id, user_id, send_event_id, event_type, payload_json, status,
            attempt_count, next_attempt_at, last_attempt_at, response_status,
            response_body_preview, error, created_at
          ) VALUES (?, ?, ?, ?, '{}', 'pending', 0, ?, NULL, NULL, '', '', ?)
        `)
        .run(
          webhook.id,
          sendEvent.userId,
          normalizedEvent.id,
          eventType,
          createdAt,
          createdAt
        );
      if (insert.changes !== 1) {
        if (manageTransactions) database.exec('ROLLBACK');
        continue;
      }
      const deliveryId = insert.lastInsertRowid;
      const payload = buildWebhookPayload({
        deliveryId,
        eventType: externalType,
        createdAt,
        sendEvent: normalizedEvent,
        engagement: options.engagement || null,
        test: false
      });
      database
        .prepare('UPDATE webhook_deliveries SET payload_json = ? WHERE id = ?')
        .run(JSON.stringify(payload), deliveryId);
      if (manageTransactions) database.exec('COMMIT');
      created.push(publicWebhookDelivery(
        database.prepare('SELECT * FROM webhook_deliveries WHERE id = ?').get(deliveryId)
      ));
    } catch (error) {
      if (manageTransactions) {
        try {
          database.exec('ROLLBACK');
        } catch {
          // ignore rollback errors when no transaction is open
        }
      }
      throw error;
    }
  }
  return created;
}

export function claimWebhookDeliveries(limit = 3) {
  const batchLimit = Math.max(1, Math.min(50, Number(limit) || 3));
  const claimedAt = now();
  const leaseUntil = new Date(Date.now() + WEBHOOK_LEASE_MS).toISOString();
  const database = requireDb();
  database.exec('BEGIN');
  try {
    const rows = database
      .prepare(`
        SELECT d.*, w.url AS webhook_url, w.secret_ciphertext AS webhook_secret_ciphertext
        FROM webhook_deliveries d
        JOIN webhooks w ON w.id = d.webhook_id
        WHERE d.status = 'pending' AND d.next_attempt_at <= ?
        ORDER BY d.next_attempt_at ASC, d.id ASC
        LIMIT ?
      `)
      .all(claimedAt, batchLimit);

    const claimed = [];
    for (const row of rows) {
      const update = database
        .prepare(`
          UPDATE webhook_deliveries
          SET status = 'processing', last_attempt_at = ?, next_attempt_at = ?
          WHERE id = ? AND status = 'pending'
        `)
        .run(claimedAt, leaseUntil, row.id);
      if (update.changes !== 1) continue;
      claimed.push({
        delivery: publicWebhookDelivery({
          ...row,
          status: 'processing',
          last_attempt_at: claimedAt,
          next_attempt_at: leaseUntil
        }),
        webhook: {
          id: row.webhook_id,
          url: row.webhook_url,
          secret: decryptSecret(row.webhook_secret_ciphertext)
        }
      });
    }
    database.exec('COMMIT');
    return claimed;
  } catch (error) {
    try {
      database.exec('ROLLBACK');
    } catch {
      // ignore
    }
    throw error;
  }
}

export function reapExpiredWebhookProcessing() {
  const reapedAt = now();
  const result = requireDb()
    .prepare(`
      UPDATE webhook_deliveries
      SET status = 'pending', next_attempt_at = ?
      WHERE status = 'processing' AND next_attempt_at < ?
    `)
    .run(reapedAt, reapedAt);
  return result.changes;
}

export function completeWebhookDeliverySuccess(id, { responseStatus = null, bodyPreview = '' } = {}) {
  const row = requireDb().prepare('SELECT * FROM webhook_deliveries WHERE id = ?').get(id);
  if (!row) return null;
  const attemptCount = Number(row.attempt_count || 0) + 1;
  const completedAt = now();
  requireDb()
    .prepare(`
      UPDATE webhook_deliveries
      SET status = 'success',
          attempt_count = ?,
          last_attempt_at = ?,
          next_attempt_at = ?,
          response_status = ?,
          response_body_preview = ?,
          error = ''
      WHERE id = ?
    `)
    .run(
      attemptCount,
      completedAt,
      completedAt,
      responseStatus,
      truncateWebhookBodyPreview(bodyPreview),
      id
    );
  return publicWebhookDelivery(requireDb().prepare('SELECT * FROM webhook_deliveries WHERE id = ?').get(id));
}

export function completeWebhookDeliveryFailure(
  id,
  { responseStatus = null, bodyPreview = '', error = '', permanent = false } = {}
) {
  const row = requireDb().prepare('SELECT * FROM webhook_deliveries WHERE id = ?').get(id);
  if (!row) return null;
  const attemptCount = Number(row.attempt_count || 0) + 1;
  const completedAt = now();
  // Permanent failures (SSRF blocked, invalid URL, missing secret) skip backoff and die immediately.
  const exhausted = permanent || attemptCount >= MAX_WEBHOOK_ATTEMPTS;
  const nextStatus = exhausted ? 'dead' : 'pending';
  const nextAttemptAt = exhausted
    ? completedAt
    : new Date(Date.now() + nextBackoffMs(attemptCount)).toISOString();
  requireDb()
    .prepare(`
      UPDATE webhook_deliveries
      SET status = ?,
          attempt_count = ?,
          last_attempt_at = ?,
          next_attempt_at = ?,
          response_status = ?,
          response_body_preview = ?,
          error = ?
      WHERE id = ?
    `)
    .run(
      nextStatus,
      attemptCount,
      completedAt,
      nextAttemptAt,
      responseStatus,
      truncateWebhookBodyPreview(bodyPreview),
      String(error || ''),
      id
    );
  return publicWebhookDelivery(requireDb().prepare('SELECT * FROM webhook_deliveries WHERE id = ?').get(id));
}

export function listWebhookDeliveries(userId, filters = {}) {
  const where = ['user_id = ?'];
  const params = [userId];
  if (filters.status) {
    where.push('status = ?');
    params.push(String(filters.status));
  }
  if (filters.webhookId != null) {
    where.push('webhook_id = ?');
    params.push(Number(filters.webhookId));
  }
  if (filters.eventType) {
    where.push('event_type = ?');
    params.push(String(filters.eventType));
  }
  if (filters.sendEventId != null) {
    where.push('send_event_id = ?');
    params.push(Number(filters.sendEventId));
  }
  const limit = Math.max(1, Math.min(200, Number(filters.limit) || 50));
  params.push(limit);
  return requireDb()
    .prepare(`
      SELECT *
      FROM webhook_deliveries
      WHERE ${where.join(' AND ')}
      ORDER BY created_at DESC, id DESC
      LIMIT ?
    `)
    .all(...params)
    .map(publicWebhookDelivery);
}

export function getWebhookDelivery(id, userId) {
  const row = requireDb()
    .prepare('SELECT * FROM webhook_deliveries WHERE id = ? AND user_id = ?')
    .get(id, userId);
  return publicWebhookDelivery(row);
}

export function replayWebhookDelivery(userId, id) {
  const row = requireDb()
    .prepare('SELECT * FROM webhook_deliveries WHERE id = ? AND user_id = ?')
    .get(id, userId);
  if (!row) return null;
  if (row.status === 'processing') {
    throw new Error('Webhook 正在投递中，请等待完成或租约过期后再重放。');
  }
  const resetAt = now();
  requireDb()
    .prepare(`
      UPDATE webhook_deliveries
      SET status = 'pending',
          attempt_count = 0,
          next_attempt_at = ?,
          last_attempt_at = NULL,
          response_status = NULL,
          response_body_preview = '',
          error = ''
      WHERE id = ? AND user_id = ?
    `)
    .run(resetAt, id, userId);
  return getWebhookDelivery(id, userId);
}

export function enqueueWebhookTestDelivery(userId, webhookId) {
  const webhook = getWebhookRow(webhookId, userId);
  if (!webhook) return null;

  const events = parseWebhookEventsJson(webhook.events_json);
  const eventType = events[0] || 'sent';
  const externalType = eventTypeForStatus(eventType) || 'email.sent';
  const firstDomain = requireDb()
    .prepare('SELECT domain FROM domains WHERE user_id = ? ORDER BY created_at ASC, id ASC LIMIT 1')
    .get(userId);
  const domainName = firstDomain?.domain || 'example.com';
  const sendEvent = {
    id: 0,
    status: eventType,
    queueId: '',
    domain: domainName,
    sender: `noreply@${domainName}`,
    recipients: ['webhook-test@example.com'],
    subject: 'MailHub webhook test',
    detail: 'test delivery',
    deliveredAt: null
  };

  const database = requireDb();
  database.exec('BEGIN');
  try {
    const existing = database
      .prepare(`
        SELECT * FROM webhook_deliveries
        WHERE webhook_id = ? AND send_event_id = 0 AND event_type = ?
      `)
      .get(webhook.id, eventType);

    if (existing) {
      if (existing.status === 'processing') {
        database.exec('ROLLBACK');
        throw new Error('Webhook 正在投递中，请等待完成或租约过期后再测试。');
      }
      const resetAt = now();
      database
        .prepare(`
          UPDATE webhook_deliveries
          SET status = 'pending',
              attempt_count = 0,
              next_attempt_at = ?,
              last_attempt_at = NULL,
              response_status = NULL,
              response_body_preview = '',
              error = ''
          WHERE id = ?
        `)
        .run(resetAt, existing.id);
      database.exec('COMMIT');
      return publicWebhookDelivery(
        database.prepare('SELECT * FROM webhook_deliveries WHERE id = ?').get(existing.id)
      );
    }

    const createdAt = now();
    const insert = database
      .prepare(`
        INSERT INTO webhook_deliveries (
          webhook_id, user_id, send_event_id, event_type, payload_json, status,
          attempt_count, next_attempt_at, last_attempt_at, response_status,
          response_body_preview, error, created_at
        ) VALUES (?, ?, 0, ?, '{}', 'pending', 0, ?, NULL, NULL, '', '', ?)
      `)
      .run(webhook.id, userId, eventType, createdAt, createdAt);
    if (insert.changes !== 1) {
      database.exec('ROLLBACK');
      return null;
    }
    const deliveryId = insert.lastInsertRowid;
    const payload = buildWebhookPayload({
      deliveryId,
      eventType: externalType,
      createdAt,
      sendEvent,
      test: true
    });
    database
      .prepare('UPDATE webhook_deliveries SET payload_json = ? WHERE id = ?')
      .run(JSON.stringify(payload), deliveryId);
    database.exec('COMMIT');
    return publicWebhookDelivery(
      database.prepare('SELECT * FROM webhook_deliveries WHERE id = ?').get(deliveryId)
    );
  } catch (error) {
    try {
      database.exec('ROLLBACK');
    } catch {
      // ignore
    }
    throw error;
  }
}

export function getSendAnalytics(userId, { days = 7, trackingSecret = '' } = {}) {
  const windowDays = clampAnalyticsDays(days);
  const since = new Date();
  since.setUTCHours(0, 0, 0, 0);
  since.setUTCDate(since.getUTCDate() - (windowDays - 1));
  const database = requireDb();
  const sinceIso = since.toISOString();
  const domains = listDomains(userId);
  const dayBuckets = buildDayBuckets(windowDays);
  const hourly = Array.from({ length: 24 }, (_, hour) => ({
    hour,
    total: 0,
    queued: 0,
    failed: 0,
    accepted: 0,
    delivered: 0,
    pending: 0,
    terminalFailed: 0
  }));
  const todayKey = new Date().toISOString().slice(0, 10);
  const weekStart = new Date();
  weekStart.setUTCHours(0, 0, 0, 0);
  weekStart.setUTCDate(weekStart.getUTCDate() - 6);
  const status = "LOWER(COALESCE(e.status, 'unknown'))";
  const recipients = "CASE WHEN json_valid(e.recipients) THEN json_array_length(e.recipients) ELSE 0 END";
  const accepted = `(COALESCE(TRIM(e.queue_id), '') != '' OR ${status} IN ('queued', 'sent', 'deferred', 'bounced'))`;
  const aggregateColumns = `
    COUNT(*) AS total,
    COALESCE(SUM(${recipients}), 0) AS recipients,
    SUM(CASE WHEN ${status} IN ('queued', 'sent') THEN 1 ELSE 0 END) AS queued,
    SUM(CASE WHEN ${status} IN ('queued', 'sent') THEN 0 ELSE 1 END) AS failed,
    SUM(CASE WHEN ${accepted} THEN 1 ELSE 0 END) AS accepted,
    SUM(CASE WHEN ${status} = 'sent' THEN 1 ELSE 0 END) AS delivered,
    SUM(CASE WHEN ${status} IN ('queued', 'deferred') THEN 1 ELSE 0 END) AS pending,
    SUM(CASE WHEN ${status} = 'deferred' THEN 1 ELSE 0 END) AS deferred,
    SUM(CASE WHEN ${status} = 'bounced' THEN 1 ELSE 0 END) AS bounced,
    SUM(CASE WHEN ${status} IN ('bounced', 'failed') THEN 1 ELSE 0 END) AS terminal_failed
  `;
  const summaryRow = database
    .prepare(`
      SELECT
        ${aggregateColumns},
        SUM(CASE WHEN substr(e.created_at, 1, 10) = ? THEN 1 ELSE 0 END) AS today,
        SUM(CASE WHEN e.created_at >= ? THEN 1 ELSE 0 END) AS last_7_days
      FROM send_events e
      WHERE e.user_id = ? AND e.created_at >= ?
    `)
    .get(todayKey, weekStart.toISOString(), userId, sinceIso);
  const summary = analyticsAggregateRow(summaryRow);

  const dayRows = database
    .prepare(`
      SELECT substr(e.created_at, 1, 10) AS day, ${aggregateColumns}
      FROM send_events e
      WHERE e.user_id = ? AND e.created_at >= ?
      GROUP BY substr(e.created_at, 1, 10)
    `)
    .all(userId, sinceIso);
  for (const row of dayRows) {
    if (!dayBuckets.has(row.day)) continue;
    dayBuckets.set(row.day, { day: row.day, ...analyticsAggregateRow(row) });
  }

  const byStatus = database
    .prepare(`
      SELECT ${status} AS status, COUNT(*) AS total
      FROM send_events e
      WHERE e.user_id = ? AND e.created_at >= ?
      GROUP BY ${status}
      ORDER BY total DESC, status ASC
    `)
    .all(userId, sinceIso)
    .map((row) => ({ status: row.status, total: Number(row.total || 0) }));

  const domainName = `COALESCE(
    NULLIF(d.domain, ''),
    CASE WHEN instr(e.sender, '@') > 0 THEN substr(e.sender, instr(e.sender, '@') + 1) ELSE 'unknown' END
  )`;
  const byDomain = database
    .prepare(`
      SELECT ${domainName} AS domain, ${aggregateColumns}
      FROM send_events e
      LEFT JOIN domains d ON d.id = e.domain_id
      WHERE e.user_id = ? AND e.created_at >= ?
      GROUP BY ${domainName}
      ORDER BY total DESC, domain ASC
      LIMIT 10
    `)
    .all(userId, sinceIso)
    .map((row) => ({ domain: row.domain, ...analyticsAggregateRow(row) }));

  const hourlyRows = database
    .prepare(`
      SELECT CAST(strftime('%H', e.created_at) AS INTEGER) AS hour, ${aggregateColumns}
      FROM send_events e
      WHERE e.user_id = ? AND e.created_at >= ?
      GROUP BY CAST(strftime('%H', e.created_at) AS INTEGER)
    `)
    .all(userId, sinceIso);
  for (const row of hourlyRows) {
    const hour = Number(row.hour);
    if (!Number.isInteger(hour) || hour < 0 || hour > 23) continue;
    hourly[hour] = { hour, ...analyticsAggregateRow(row) };
  }

  const failureReason = `normalize_failure_reason(e.detail, ${status})`;
  const failureReasons = database
    .prepare(`
      WITH failures AS (
        SELECT ${failureReason} AS reason, ${status} AS status, e.created_at
        FROM send_events e
        WHERE e.user_id = ? AND e.created_at >= ?
          AND ${status} IN ('deferred', 'bounced', 'failed')
      ), grouped AS (
        SELECT reason, status, COUNT(*) AS total, MAX(created_at) AS last_seen_at
        FROM failures
        GROUP BY reason, status
      )
      SELECT
        reason,
        SUM(total) AS total,
        json_group_object(status, total) AS statuses,
        MAX(last_seen_at) AS last_seen_at
      FROM grouped
      GROUP BY reason
      ORDER BY total DESC, last_seen_at DESC
      LIMIT 10
    `)
    .all(userId, sinceIso)
    .map((row) => ({
      reason: row.reason,
      total: Number(row.total || 0),
      statuses: safeJson(row.statuses, {}),
      lastSeenAt: row.last_seen_at
    }));

  const recentFailures = database
    .prepare(`
      SELECT e.id, d.domain, e.sender, e.subject, e.detail, e.created_at
      FROM send_events e
      LEFT JOIN domains d ON d.id = e.domain_id
      WHERE e.user_id = ? AND e.created_at >= ?
        AND ${status} IN ('deferred', 'bounced', 'failed')
      ORDER BY e.created_at DESC, e.id DESC
      LIMIT 8
    `)
    .all(userId, sinceIso)
    .map((row) => ({
      id: row.id,
      domain: row.domain || '',
      sender: row.sender,
      subject: row.subject,
      detail: row.detail,
      createdAt: row.created_at
    }));
  const engagementAnalytics = buildEngagementAnalytics(userId, {
    since: sinceIso,
    windowDays,
    trackingSecret
  });

  return {
    windowDays,
    summary: {
      ...summary,
      submitted: summary.total,
      today: Number(summaryRow?.today || 0),
      last7Days: Number(summaryRow?.last_7_days || 0),
      successRate: percent(summary.queued, summary.total),
      acceptanceRate: percent(summary.accepted, summary.total),
      deliveryRate: percent(summary.delivered, summary.total),
      failureRate: percent(summary.terminalFailed, summary.total),
      domains: domains.length,
      verifiedDomains: domains.filter((domain) => domain.status?.verified).length
    },
    deliveryFunnel: [
      { stage: 'submitted', total: summary.total, rate: percent(summary.total, summary.total) },
      { stage: 'accepted', total: summary.accepted, rate: percent(summary.accepted, summary.total) },
      { stage: 'delivered', total: summary.delivered, rate: percent(summary.delivered, summary.total) },
      { stage: 'pending', total: summary.pending, rate: percent(summary.pending, summary.total) },
      { stage: 'failed', total: summary.terminalFailed, rate: percent(summary.terminalFailed, summary.total) }
    ],
    byDay: [...dayBuckets.values()],
    byDomain,
    byStatus,
    hourly,
    ...engagementAnalytics,
    failureReasons,
    recentFailures
  };
}

function analyticsAggregateRow(row) {
  return {
    total: Number(row?.total || 0),
    queued: Number(row?.queued || 0),
    failed: Number(row?.failed || 0),
    accepted: Number(row?.accepted || 0),
    delivered: Number(row?.delivered || 0),
    pending: Number(row?.pending || 0),
    deferred: Number(row?.deferred || 0),
    bounced: Number(row?.bounced || 0),
    terminalFailed: Number(row?.terminal_failed || 0),
    recipients: Number(row?.recipients || 0)
  };
}

function buildEngagementAnalytics(userId, { since, windowDays, trackingSecret }) {
  const database = requireDb();
  const deliveredCte = `
    WITH delivered AS (
      SELECT e.id
      FROM send_events e
      WHERE e.user_id = ?
        AND e.created_at >= ?
        AND (e.tracking_opens = 'true' OR e.tracking_clicks = 'true')
        AND (
          e.status = 'sent'
          OR EXISTS (
            SELECT 1
            FROM json_each(
              CASE WHEN json_valid(e.delivery_attempts_json) THEN e.delivery_attempts_json ELSE '[]' END
            ) attempt
            WHERE json_extract(attempt.value, '$.status') = 'sent'
          )
        )
    )
  `;
  const summary = database
    .prepare(`
      ${deliveredCte}
      SELECT
        (SELECT COUNT(*) FROM delivered) AS tracked_delivered,
        COALESCE(SUM(CASE WHEN te.event_type = 'open' AND te.source != 'scanner' THEN 1 ELSE 0 END), 0) AS total_opens,
        COUNT(DISTINCT CASE
          WHEN (te.event_type = 'open' AND te.source != 'scanner')
            OR (te.event_type = 'click' AND te.source = 'direct')
          THEN te.send_event_id END
        ) AS unique_opens,
        COALESCE(SUM(CASE WHEN te.event_type = 'open' AND te.source = 'proxy' THEN 1 ELSE 0 END), 0) AS proxy_opens,
        COALESCE(SUM(CASE WHEN te.event_type = 'click' AND te.source = 'direct' THEN 1 ELSE 0 END), 0) AS total_clicks,
        COUNT(DISTINCT CASE
          WHEN te.event_type = 'click' AND te.source = 'direct' THEN te.send_event_id END
        ) AS unique_clicks,
        COALESCE(SUM(CASE WHEN te.source = 'scanner' THEN 1 ELSE 0 END), 0) AS scanner_events
      FROM tracking_events te
      JOIN delivered d ON d.id = te.send_event_id
    `)
    .get(userId, since);
  const trackedDelivered = Number(summary?.tracked_delivered || 0);
  const uniqueOpens = Number(summary?.unique_opens || 0);
  const uniqueClicks = Number(summary?.unique_clicks || 0);
  const engagement = {
    trackedDelivered,
    totalOpens: Number(summary?.total_opens || 0),
    uniqueOpens,
    proxyOpens: Number(summary?.proxy_opens || 0),
    totalClicks: Number(summary?.total_clicks || 0),
    uniqueClicks,
    scannerEvents: Number(summary?.scanner_events || 0),
    openRate: percent(uniqueOpens, trackedDelivered),
    clickRate: percent(uniqueClicks, trackedDelivered),
    clickToOpenRate: percent(uniqueClicks, uniqueOpens)
  };

  const engagementByDay = buildEngagementDayBuckets(windowDays);
  const dayRows = database
    .prepare(`
      ${deliveredCte}
      SELECT
        substr(te.occurred_at, 1, 10) AS day,
        SUM(CASE WHEN te.event_type = 'open' AND te.source != 'scanner' THEN 1 ELSE 0 END) AS opens,
        COUNT(DISTINCT CASE
          WHEN (te.event_type = 'open' AND te.source != 'scanner')
            OR (te.event_type = 'click' AND te.source = 'direct')
          THEN te.send_event_id END
        ) AS unique_opens,
        SUM(CASE WHEN te.event_type = 'click' AND te.source = 'direct' THEN 1 ELSE 0 END) AS clicks,
        COUNT(DISTINCT CASE
          WHEN te.event_type = 'click' AND te.source = 'direct' THEN te.send_event_id END
        ) AS unique_clicks,
        SUM(CASE WHEN te.source = 'scanner' THEN 1 ELSE 0 END) AS scanner_events
      FROM tracking_events te
      JOIN delivered d ON d.id = te.send_event_id
      WHERE te.occurred_at >= ?
      GROUP BY substr(te.occurred_at, 1, 10)
    `)
    .all(userId, since, since);
  for (const row of dayRows) {
    if (!engagementByDay.has(row.day)) continue;
    engagementByDay.set(row.day, {
      day: row.day,
      opens: Number(row.opens || 0),
      uniqueOpens: Number(row.unique_opens || 0),
      clicks: Number(row.clicks || 0),
      uniqueClicks: Number(row.unique_clicks || 0),
      scannerEvents: Number(row.scanner_events || 0)
    });
  }

  const topLinks = database
    .prepare(`
      ${deliveredCte}
      SELECT
        tl.target_fingerprint,
        MIN(tl.target_ciphertext) AS target_ciphertext,
        MIN(tl.target_origin) AS target_origin,
        COUNT(*) AS clicks,
        COUNT(DISTINCT te.send_event_id) AS unique_clicks,
        MAX(te.occurred_at) AS last_clicked_at
      FROM tracking_events te
      JOIN delivered d ON d.id = te.send_event_id
      JOIN tracking_links tl ON tl.id = te.tracking_link_id
      WHERE te.event_type = 'click' AND te.source = 'direct' AND te.occurred_at >= ?
      GROUP BY tl.target_fingerprint
      ORDER BY clicks DESC, last_clicked_at DESC
      LIMIT 20
    `)
    .all(userId, since, since)
    .map((row) => ({
      fingerprint: row.target_fingerprint,
      target: decryptTrackingTargetForOwner(row.target_ciphertext, row.target_origin, trackingSecret),
      targetOrigin: row.target_origin,
      clicks: Number(row.clicks || 0),
      uniqueClicks: Number(row.unique_clicks || 0),
      lastClickedAt: row.last_clicked_at
    }));

  return {
    engagement,
    engagementByDay: [...engagementByDay.values()],
    topLinks
  };
}

function buildEngagementDayBuckets(days) {
  const buckets = new Map();
  const start = new Date();
  start.setUTCHours(0, 0, 0, 0);
  start.setUTCDate(start.getUTCDate() - (days - 1));
  for (let index = 0; index < days; index += 1) {
    const date = new Date(start);
    date.setUTCDate(date.getUTCDate() + index);
    const day = date.toISOString().slice(0, 10);
    buckets.set(day, { day, opens: 0, uniqueOpens: 0, clicks: 0, uniqueClicks: 0, scannerEvents: 0 });
  }
  return buckets;
}

function decryptTrackingTargetForOwner(ciphertext, fallback, trackingSecret) {
  if (!trackingSecret) return fallback || '';
  try {
    return decryptTrackingTarget(ciphertext, trackingSecret);
  } catch {
    return fallback || '';
  }
}

export function listSmtpCredentials(userId, { includePassword = false, includeSecret = false } = {}) {
  return requireDb()
    .prepare('SELECT * FROM smtp_credentials WHERE user_id = ? ORDER BY created_at DESC, id DESC')
    .all(userId)
    .map((row) => publicSmtpCredential(row, { includePassword, includeSecret }));
}

export function getSmtpCredential(idOrUserId, userIdOrOptions = {}, maybeOptions = {}) {
  const scopedLookup = typeof userIdOrOptions === 'number';
  const options = scopedLookup ? maybeOptions : userIdOrOptions;
  const { includeHash = false, includePassword = false, includeSecret = false } = options || {};
  const row = scopedLookup
    ? requireDb()
      .prepare('SELECT * FROM smtp_credentials WHERE id = ? AND user_id = ?')
      .get(Number(idOrUserId), Number(userIdOrOptions))
    : requireDb()
      .prepare('SELECT * FROM smtp_credentials WHERE user_id = ? ORDER BY created_at DESC, id DESC LIMIT 1')
      .get(Number(idOrUserId));
  if (!row) return null;
  return publicSmtpCredential(row, { includeHash, includePassword, includeSecret });
}

export function saveSmtpCredential(userId, { id = null, username, password }) {
  const current = id ? getSmtpCredential(id, userId, { includeHash: true, includeSecret: true }) : null;
  if (id && !current) return null;
  const nextUsername = String(username || current?.username || '').trim();
  if (!nextUsername) throw new Error('SMTP 用户名不能为空。');
  const nextHash = password ? hashPassword(password) : current?.passwordHash;
  if (!nextHash) throw new Error('SMTP 密码不能为空。');
  const nextSecret = password ? encryptSecret(password) : current?.passwordSecret || '';
  const updatedAt = now();
  if (current) {
    requireDb()
      .prepare('UPDATE smtp_credentials SET username = ?, password_hash = ?, password_secret = ?, updated_at = ? WHERE id = ? AND user_id = ?')
      .run(nextUsername, nextHash, nextSecret, updatedAt, current.id, userId);
    return getSmtpCredential(current.id, userId);
  } else {
    const result = requireDb()
      .prepare(`
        INSERT INTO smtp_credentials (user_id, username, password_hash, password_secret, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `)
      .run(userId, nextUsername, nextHash, nextSecret, updatedAt, updatedAt);
    return getSmtpCredential(result.lastInsertRowid, userId);
  }
}

export function deleteSmtpCredential(id, userId) {
  const result = requireDb()
    .prepare('DELETE FROM smtp_credentials WHERE id = ? AND user_id = ?')
    .run(Number(id), userId);
  return result.changes > 0;
}

export function listSmtpRelays(userId, { includePassword = false, includeSecret = false } = {}) {
  return requireDb()
    .prepare('SELECT * FROM smtp_relays WHERE user_id = ? ORDER BY is_default DESC, created_at DESC')
    .all(userId)
    .map((row) => publicSmtpRelay(row, { includePassword, includeSecret }));
}

export function getSmtpRelay(id, userId, { includePassword = false, includeSecret = false } = {}) {
  const row = requireDb()
    .prepare('SELECT * FROM smtp_relays WHERE id = ? AND user_id = ?')
    .get(Number(id), userId);
  return publicSmtpRelay(row, { includePassword, includeSecret });
}

export function getDefaultSmtpRelay(userId, { includePassword = false, includeSecret = false } = {}) {
  const row = requireDb()
    .prepare("SELECT * FROM smtp_relays WHERE user_id = ? AND is_default = 'true' ORDER BY updated_at DESC LIMIT 1")
    .get(userId);
  return publicSmtpRelay(row, { includePassword, includeSecret });
}

export function saveSmtpRelay(userId, relay = {}) {
  const current = relay.id ? getSmtpRelay(relay.id, userId, { includeSecret: true }) : null;
  if (relay.id && !current) return null;
  const name = String(relay.name ?? current?.name ?? '').trim() || 'SMTP Relay';
  const host = String(relay.host ?? current?.host ?? '').trim();
  if (!host) throw new Error('SMTP Host 不能为空。');
  const port = normalizePort(relay.port ?? current?.port, 587);
  const secure = boolString(relay.secure ?? current?.secure ?? false);
  const username = String(relay.username ?? current?.username ?? '').trim();
  const passwordSecret = Object.hasOwn(relay, 'password')
    ? encryptSecret(relay.password)
    : current?.passwordSecret || '';
  const helo = String(relay.helo ?? current?.helo ?? '').trim();
  const isDefault = boolString(relay.isDefault ?? current?.isDefault ?? false);
  const updatedAt = now();

  return withTransaction(() => {
    if (isDefault === 'true') clearDefaultSmtpRelay(userId);
    if (current) {
      requireDb()
        .prepare(`
          UPDATE smtp_relays
          SET name = ?, host = ?, port = ?, secure = ?, username = ?, password_secret = ?,
              helo = ?, is_default = ?, updated_at = ?
          WHERE id = ? AND user_id = ?
        `)
        .run(name, host, port, secure, username, passwordSecret, helo, isDefault, updatedAt, current.id, userId);
      return getSmtpRelay(current.id, userId);
    }
    const result = requireDb()
      .prepare(`
        INSERT INTO smtp_relays (
          user_id, name, host, port, secure, username, password_secret,
          helo, is_default, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `)
      .run(userId, name, host, port, secure, username, passwordSecret, helo, isDefault, updatedAt, updatedAt);
    return getSmtpRelay(result.lastInsertRowid, userId);
  });
}

export function deleteSmtpRelay(id, userId) {
  return withTransaction(() => {
    requireDb()
      .prepare('UPDATE domains SET smtp_relay_id = NULL WHERE smtp_relay_id = ? AND user_id = ?')
      .run(Number(id), userId);
    const result = requireDb()
      .prepare('DELETE FROM smtp_relays WHERE id = ? AND user_id = ?')
      .run(Number(id), userId);
    return result.changes > 0;
  });
}

function clearDefaultSmtpRelay(userId) {
  requireDb()
    .prepare("UPDATE smtp_relays SET is_default = 'false', updated_at = ? WHERE user_id = ?")
    .run(now(), userId);
}

export function verifySmtpCredential(username, password) {
  const cleanUsername = String(username || '').trim();
  const row = requireDb()
    .prepare(`
      SELECT c.*, u.id AS auth_user_id, u.username AS auth_username, u.email, u.role, u.status
      FROM smtp_credentials c
      JOIN users u ON u.id = c.user_id
      WHERE c.username = ?
    `)
    .get(cleanUsername);
  if (row && row.status === 'active' && verifyPassword(password, row.password_hash)) {
    return {
      user: {
        id: row.auth_user_id,
        username: row.auth_username,
        email: row.email,
        role: row.role,
        status: row.status
      },
      credential: publicSmtpCredential(row)
    };
  }

  const mailboxAuth = verifyInboundMailboxCredential(cleanUsername, password);
  return mailboxAuth ? {
    user: mailboxAuth.user,
    mailbox: mailboxAuth.mailbox,
    credential: {
      username: mailboxAuth.mailbox.address,
      type: 'inbound_mailbox'
    }
  } : null;
}

export function createApiToken(userId, name, { scopes, expiresAt } = {}) {
  const token = `mh_${crypto.randomBytes(32).toString('base64url')}`;
  const createdAt = now();
  const cleanScopes = normalizeApiTokenScopes(scopes);
  const cleanExpiresAt = normalizeApiTokenExpiresAt(expiresAt);
  const result = requireDb()
    .prepare(`
      INSERT INTO api_tokens (user_id, name, token_hash, token_prefix, scopes_json, expires_at, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `)
    .run(
      userId,
      normalizeApiTokenName(name),
      tokenHash(token),
      token.slice(0, 12),
      JSON.stringify(cleanScopes),
      cleanExpiresAt,
      createdAt
    );
  return {
    ...getApiToken(result.lastInsertRowid, userId),
    token
  };
}

export function listApiTokens(userId) {
  return requireDb()
    .prepare('SELECT * FROM api_tokens WHERE user_id = ? ORDER BY created_at DESC')
    .all(userId)
    .map(publicApiToken);
}

export function getApiToken(id, userId) {
  const row = requireDb()
    .prepare('SELECT * FROM api_tokens WHERE id = ? AND user_id = ?')
    .get(id, userId);
  return publicApiToken(row);
}

export function updateApiToken(id, userId, patch = {}) {
  const current = requireDb()
    .prepare('SELECT * FROM api_tokens WHERE id = ? AND user_id = ?')
    .get(Number(id), userId);
  if (!current) return null;
  if (current.revoked_at) throw new Error('已撤销的 API Token 不能修改。');
  const name = Object.hasOwn(patch, 'name') ? normalizeApiTokenName(patch.name) : current.name;
  const scopes = Object.hasOwn(patch, 'scopes')
    ? normalizeApiTokenScopes(patch.scopes)
    : storedApiTokenScopes(current.scopes_json);
  const expiresAt = Object.hasOwn(patch, 'expiresAt')
    ? normalizeApiTokenExpiresAt(patch.expiresAt)
    : current.expires_at || null;
  requireDb()
    .prepare('UPDATE api_tokens SET name = ?, scopes_json = ?, expires_at = ? WHERE id = ? AND user_id = ?')
    .run(name, JSON.stringify(scopes), expiresAt, Number(id), userId);
  return getApiToken(id, userId);
}

export function revokeApiToken(id, userId, reason = '') {
  const result = requireDb()
    .prepare(`
      UPDATE api_tokens
      SET revoked_at = ?, revoked_reason = ?
      WHERE id = ? AND user_id = ? AND revoked_at IS NULL
    `)
    .run(now(), String(reason || '').trim().slice(0, 200), Number(id), userId);
  return result.changes > 0;
}

export function deleteApiToken(id, userId) {
  const result = requireDb().prepare('DELETE FROM api_tokens WHERE id = ? AND user_id = ?').run(id, userId);
  return result.changes > 0;
}

export function verifyApiToken(token) {
  return authenticateApiToken(token)?.user || null;
}

export function authenticateApiToken(token) {
  const hash = tokenHash(token);
  const row = requireDb()
    .prepare(`
      SELECT t.*, u.id AS auth_user_id, u.username, u.email, u.role, u.status
      FROM api_tokens t
      JOIN users u ON u.id = t.user_id
      WHERE t.token_hash = ?
    `)
    .get(hash);
  if (!row || row.status !== 'active' || apiTokenStatus(row) !== 'active') return null;
  requireDb().prepare('UPDATE api_tokens SET last_used_at = ? WHERE id = ?').run(now(), row.id);
  return {
    user: {
      id: row.auth_user_id,
      username: row.username,
      email: row.email,
      role: row.role,
      status: row.status
    },
    token: publicApiToken(row)
  };
}

export function createAccountToken(userId, purpose, { ttlMinutes } = {}) {
  const cleanPurpose = normalizeAccountTokenPurpose(purpose);
  const ttl = Number(ttlMinutes);
  if (!Number.isInteger(ttl) || ttl < 1 || ttl > maxAccountTokenTtlMinutes) throw new Error('令牌有效期不正确。');
  const token = crypto.randomBytes(32).toString('base64url');
  const createdAt = now();
  const expiresAt = new Date(Date.now() + ttl * 60 * 1000).toISOString();
  const result = requireDb()
    .prepare(`
      INSERT INTO account_tokens (user_id, purpose, token_hash, expires_at, created_at)
      VALUES (?, ?, ?, ?, ?)
    `)
    .run(userId, cleanPurpose, tokenHash(token), expiresAt, createdAt);
  return {
    ...publicAccountToken(getAccountTokenRow(result.lastInsertRowid)),
    token
  };
}

export function consumeAccountToken(token, purpose) {
  const rawToken = String(token || '');
  const cleanPurpose = String(purpose || '').trim();
  if (!rawToken || !cleanPurpose) return null;
  const tokenDigest = tokenHash(rawToken);
  const usedAt = now();
  const result = requireDb()
    .prepare(`
      UPDATE account_tokens
      SET used_at = ?
      WHERE token_hash = ? AND purpose = ? AND used_at IS NULL AND expires_at > ?
    `)
    .run(usedAt, tokenDigest, cleanPurpose, usedAt);
  if (result.changes === 0) return null;
  const row = requireDb()
    .prepare('SELECT * FROM account_tokens WHERE token_hash = ? AND purpose = ?')
    .get(tokenDigest, cleanPurpose);
  return publicAccountToken(row);
}

export function invalidateAccountTokens(userId, purpose) {
  const cleanPurpose = String(purpose || '').trim();
  if (!userId || !cleanPurpose) return 0;
  const result = requireDb()
    .prepare('UPDATE account_tokens SET used_at = ? WHERE user_id = ? AND purpose = ? AND used_at IS NULL')
    .run(now(), userId, cleanPurpose);
  return result.changes;
}

export function listDnsCredentials(userId) {
  return requireDb()
    .prepare('SELECT * FROM dns_credentials WHERE user_id = ? ORDER BY created_at DESC')
    .all(userId)
    .map(publicDnsCredential);
}

export function getDnsCredential(id, userId, { includeCredentials = false } = {}) {
  const row = requireDb()
    .prepare('SELECT * FROM dns_credentials WHERE id = ? AND user_id = ?')
    .get(id, userId);
  if (!row) return null;
  const publicRow = publicDnsCredential(row);
  if (!includeCredentials) return publicRow;
  return {
    ...publicRow,
    credentials: safeJson(decryptSecret(row.credentials_secret), {})
  };
}

export function saveDnsCredential(userId, credential) {
  const provider = normalizeProvider(credential.provider);
  if (!provider) throw new Error('DNS 服务商不支持。');
  const name = String(credential.name || provider).trim();
  const zoneName = String(credential.zoneName || credential.zone || '').trim().toLowerCase();
  const defaultTtl = clampTtl(credential.defaultTtl);
  const credentials = credential.credentials || pickCredentialFields(credential);
  const updatedAt = now();
  if (credential.id) {
    const current = getDnsCredential(credential.id, userId, { includeCredentials: true });
    if (!current) return null;
    const nextCredentials = Object.keys(credentials).length ? credentials : current.credentials;
    requireDb()
      .prepare(`
        UPDATE dns_credentials
        SET name = ?, provider = ?, zone_name = ?, default_ttl = ?, credentials_secret = ?, updated_at = ?
        WHERE id = ? AND user_id = ?
      `)
      .run(name, provider, zoneName, defaultTtl, encryptSecret(JSON.stringify(nextCredentials)), updatedAt, credential.id, userId);
    return getDnsCredential(credential.id, userId);
  }
  const result = requireDb()
    .prepare(`
      INSERT INTO dns_credentials (user_id, name, provider, zone_name, default_ttl, credentials_secret, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `)
    .run(userId, name, provider, zoneName, defaultTtl, encryptSecret(JSON.stringify(credentials)), updatedAt, updatedAt);
  return getDnsCredential(result.lastInsertRowid, userId);
}

export function deleteDnsCredential(id, userId) {
  requireDb().prepare('UPDATE domains SET dns_credential_id = NULL WHERE dns_credential_id = ? AND user_id = ?').run(id, userId);
  const result = requireDb().prepare('DELETE FROM dns_credentials WHERE id = ? AND user_id = ?').run(id, userId);
  return result.changes > 0;
}

export function getSettings(defaults = {}) {
  const rows = requireDb().prepare('SELECT * FROM app_settings').all();
  const values = { ...defaults };
  for (const row of rows) values[row.key] = row.value;
  return values;
}

export function saveSettings(patch) {
  const allowed = new Set([
    'appBaseUrl',
    'mailHostname',
    'sendingIp',
    'defaultSpfMechanisms',
    'dmarcPolicy',
    'dmarcRua',
    'sendRequiresVerified',
    'engagementTrackingEnabled',
    'listUnsubscribeMailto',
    'listUnsubscribeUrl',
    'listUnsubscribePostEnabled',
    'feedbackIdEnabled',
    'reportAbuseTo',
    'csaComplaintsTo',
    'bounceAddress',
    'bounceEnvelopeEnabled'
  ]);
  const updatedAt = now();
  for (const [key, value] of Object.entries(patch)) {
    if (!allowed.has(key)) continue;
    saveAppSetting(key, String(value ?? ''), updatedAt);
  }
  return getSettings();
}

export function getSystemEmailSettings({ includeSecret = false } = {}) {
  const rows = requireDb()
    .prepare("SELECT key, value FROM app_settings WHERE key LIKE 'systemEmail.%'")
    .all();
  const values = Object.fromEntries(
    rows.map((row) => [String(row.key).replace(/^systemEmail\./, ''), row.value])
  );
  const passwordSecret = values.passwordSecret || '';
  const settings = {
    host: values.host || '',
    port: normalizePort(values.port, 587),
    secure: values.secure === 'true',
    username: values.username || '',
    helo: values.helo || '',
    fromEmail: values.fromEmail || '',
    fromName: values.fromName || '',
    testRecipient: values.testRecipient || '',
    passwordSet: Boolean(passwordSecret)
  };
  if (includeSecret) settings.password = decryptSecret(passwordSecret);
  return settings;
}

export function saveSystemEmailSettings(patch = {}) {
  const current = getSystemEmailSettings({ includeSecret: true });
  const next = {
    host: patch.host ?? current.host,
    port: patch.port ?? current.port,
    secure: patch.secure ?? current.secure,
    username: patch.username ?? current.username,
    helo: patch.helo ?? current.helo,
    fromEmail: patch.fromEmail ?? current.fromEmail,
    fromName: patch.fromName ?? current.fromName,
    testRecipient: patch.testRecipient ?? current.testRecipient
  };
  const passwordSecret = Object.hasOwn(patch, 'password') && String(patch.password || '')
    ? encryptSecret(patch.password)
    : requireDb()
        .prepare("SELECT value FROM app_settings WHERE key = 'systemEmail.passwordSecret'")
        .get()?.value || '';
  const updatedAt = now();
  const values = {
    host: String(next.host || ''),
    port: String(normalizePort(next.port, 587)),
    secure: boolString(next.secure),
    username: String(next.username || ''),
    helo: String(next.helo || ''),
    fromEmail: normalizeEmail(next.fromEmail),
    fromName: String(next.fromName || ''),
    testRecipient: normalizeEmail(next.testRecipient),
    passwordSecret
  };
  for (const [key, value] of Object.entries(values)) {
    saveAppSetting(`systemEmail.${key}`, value, updatedAt);
  }
  return getSystemEmailSettings();
}

function saveAppSetting(key, value, updatedAt = now()) {
  requireDb()
    .prepare(`
      INSERT INTO app_settings (key, value, updated_at)
      VALUES (?, ?, ?)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
    `)
    .run(key, String(value ?? ''), updatedAt);
}

function withTransaction(callback) {
  const database = requireDb();
  database.exec('BEGIN');
  try {
    const result = callback();
    database.exec('COMMIT');
    return result;
  } catch (error) {
    database.exec('ROLLBACK');
    throw error;
  }
}

function requireTransferTargetUser(targetUserId) {
  const target = getUser(Number(targetUserId));
  if (!target || target.status === 'disabled') throw new Error('目标用户不可用。');
  return target;
}

function requireMergeUsers(sourceUserId, targetUserId) {
  const source = getUser(Number(sourceUserId));
  const target = requireTransferTargetUser(targetUserId);
  if (!source) throw new Error('源用户不存在。');
  if (source.id === target.id) throw new Error('源用户和目标用户不能相同。');
  return { source, target };
}

function mergeResourcesForUser(userId) {
  return {
    domains: listDomains(userId),
    dnsCredentials: listDnsCredentials(userId),
    apiTokens: listApiTokens(userId),
    inboundMailboxes: listInboundMailboxes(userId),
    inboundMessageCount: countRows('inbound_messages', userId, 'deleted_at IS NULL'),
    sendEventCount: countRows('send_events', userId),
    smtpCredential: getSmtpCredential(userId)
  };
}

function countRows(table, userId, extraWhere = '') {
  const suffix = extraWhere ? ` AND ${extraWhere}` : '';
  return Number(requireDb().prepare(`SELECT COUNT(*) AS count FROM ${mergeResourceTable(table)} WHERE user_id = ?${suffix}`).get(userId).count || 0);
}

function moveRows(table, sourceUserId, targetUserId) {
  const result = requireDb()
    .prepare(`UPDATE ${mergeResourceTable(table)} SET user_id = ? WHERE user_id = ?`)
    .run(targetUserId, sourceUserId);
  return result.changes;
}

function mergeResourceTable(table) {
  if (!['domains', 'dns_credentials', 'api_tokens', 'inbound_mailboxes', 'inbound_messages', 'send_events', 'smtp_credentials'].includes(table)) {
    throw new Error('资源类型不正确。');
  }
  return table;
}

function moveInboundDomainResources(domainId, targetUserId) {
  const updatedAt = now();
  const mailboxResult = requireDb()
    .prepare('UPDATE inbound_mailboxes SET user_id = ?, updated_at = ? WHERE domain_id = ? AND deleted_at IS NULL')
    .run(targetUserId, updatedAt, domainId);
  const messageResult = requireDb()
    .prepare('UPDATE inbound_messages SET user_id = ?, updated_at = ? WHERE domain_id = ? AND deleted_at IS NULL')
    .run(targetUserId, updatedAt, domainId);
  requireDb()
    .prepare(`
      UPDATE inbound_folders
      SET user_id = ?, updated_at = ?
      WHERE deleted_at IS NULL
        AND mailbox_id IN (SELECT id FROM inbound_mailboxes WHERE domain_id = ?)
    `)
    .run(targetUserId, updatedAt, domainId);
  return {
    mailboxes: mailboxResult.changes,
    messages: messageResult.changes
  };
}

function moveInboundResourcesForUserDomains(sourceUserId, targetUserId) {
  const updatedAt = now();
  const mailboxResult = requireDb()
    .prepare(`
      UPDATE inbound_mailboxes
      SET user_id = ?, updated_at = ?
      WHERE user_id = ?
        AND deleted_at IS NULL
        AND domain_id IN (SELECT id FROM domains WHERE user_id = ?)
    `)
    .run(targetUserId, updatedAt, sourceUserId, sourceUserId);
  const messageResult = requireDb()
    .prepare(`
      UPDATE inbound_messages
      SET user_id = ?, updated_at = ?
      WHERE user_id = ?
        AND deleted_at IS NULL
        AND domain_id IN (SELECT id FROM domains WHERE user_id = ?)
    `)
    .run(targetUserId, updatedAt, sourceUserId, sourceUserId);
  requireDb()
    .prepare(`
      UPDATE inbound_folders
      SET user_id = ?, updated_at = ?
      WHERE user_id = ?
        AND deleted_at IS NULL
        AND mailbox_id IN (SELECT id FROM inbound_mailboxes WHERE domain_id IN (SELECT id FROM domains WHERE user_id = ?))
    `)
    .run(targetUserId, updatedAt, sourceUserId, sourceUserId);
  return {
    mailboxes: mailboxResult.changes,
    messages: messageResult.changes
  };
}

function requireDomainRow(domainId) {
  const domain = requireDb().prepare('SELECT * FROM domains WHERE id = ?').get(Number(domainId));
  if (!domain) throw new Error('域名不存在。');
  return domain;
}

function requireDnsCredentialRow(credentialId) {
  const credential = requireDb().prepare('SELECT * FROM dns_credentials WHERE id = ?').get(Number(credentialId));
  if (!credential) throw new Error('DNS 凭据不存在。');
  return credential;
}

function normalizeDnsCredentialTransferMode(value) {
  const mode = String(value || 'domain_only').trim();
  return ['domain_only', 'with_dns_credential', 'clear_dns_credential'].includes(mode) ? mode : 'domain_only';
}

function uniquePositiveIds(values) {
  return [...new Set((Array.isArray(values) ? values : [values])
    .map((value) => Number(value))
    .filter((value) => Number.isInteger(value) && value > 0))];
}

function migrateLegacySmtpTable() {
  if (!tableExists('smtp_credentials') || columnExists('smtp_credentials', 'user_id')) return;
  if (!tableExists('smtp_credentials_legacy')) {
    requireDb().exec('ALTER TABLE smtp_credentials RENAME TO smtp_credentials_legacy;');
  } else {
    requireDb().exec('DROP TABLE smtp_credentials;');
  }
}

function migrateSmtpCredentialsToMultiplePerUser() {
  if (!tableExists('smtp_credentials') || !smtpCredentialsHasUserIdUniqueConstraint()) return;
  requireDb().exec(`
    ALTER TABLE smtp_credentials RENAME TO smtp_credentials_single_user;
    CREATE TABLE smtp_credentials (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      password_secret TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    INSERT INTO smtp_credentials (id, user_id, username, password_hash, password_secret, created_at, updated_at)
    SELECT id, user_id, username, password_hash, COALESCE(password_secret, ''), created_at, updated_at
    FROM smtp_credentials_single_user;
    DROP TABLE smtp_credentials_single_user;
  `);
}

function smtpCredentialsHasUserIdUniqueConstraint() {
  const row = requireDb()
    .prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'smtp_credentials'")
    .get();
  if (/user_id\s+INTEGER\s+NOT\s+NULL\s+UNIQUE/i.test(String(row?.sql || ''))) return true;
  const indexes = requireDb().prepare('PRAGMA index_list(smtp_credentials)').all();
  return indexes.some((index) => {
    if (!index.unique) return false;
    const columns = requireDb().prepare(`PRAGMA index_info(${index.name})`).all().map((item) => item.name);
    return columns.length === 1 && columns[0] === 'user_id';
  });
}

function requireDb() {
  if (!db) throw new Error('Database is not initialized.');
  return db;
}

function tableExists(table) {
  return Boolean(requireDb().prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?").get(table));
}

function columnExists(table, column) {
  if (!tableExists(table)) return false;
  return requireDb()
    .prepare(`PRAGMA table_info(${table})`)
    .all()
    .some((row) => row.name === column);
}

function ensureColumn(table, column, definition) {
  if (!columnExists(table, column)) requireDb().exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
}

function normalizeDkimPublicKeys() {
  if (!tableExists('domains') || !columnExists('domains', 'dkim_private') || !columnExists('domains', 'dkim_public')) return;
  const rows = requireDb().prepare('SELECT id, dkim_public, dkim_private FROM domains').all();
  const update = requireDb().prepare('UPDATE domains SET dkim_public = ?, updated_at = ? WHERE id = ?');
  for (const row of rows) {
    if (!row.dkim_private) continue;
    try {
      const publicKey = dkimPublicFromPrivateKey(row.dkim_private);
      if (publicKey && publicKey !== row.dkim_public) update.run(publicKey, now(), row.id);
    } catch {
      // Leave legacy or malformed rows untouched; rotating DKIM from the UI can repair them.
    }
  }
}

function normalizeSendEventQueueIds() {
  if (!tableExists('send_events') || !columnExists('send_events', 'queue_id')) return;
  const rows = requireDb()
    .prepare("SELECT id, detail FROM send_events WHERE queue_id = '' OR queue_id IS NULL")
    .all();
  const update = requireDb().prepare('UPDATE send_events SET queue_id = ? WHERE id = ?');
  for (const row of rows) {
    const queueId = extractQueueIdFromText(row.detail);
    if (queueId) update.run(queueId, row.id);
  }
}

function publicUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    username: row.username,
    email: row.email,
    role: row.role,
    status: row.status,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

function privateUser(row) {
  const user = publicUser(row);
  return user ? { ...user, passwordHash: row.password_hash } : null;
}

function publicDomainRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    userId: row.user_id,
    dnsCredentialId: row.dns_credential_id,
    smtpRelayId: row.smtp_relay_id,
    domain: row.domain,
    selector: row.selector,
    verificationToken: row.verification_token,
    dkimPublic: row.dkim_public,
    senderHost: row.sender_host,
    sendingIp: row.sending_ip,
    spfExtra: row.spf_extra,
    dmarcPolicy: row.dmarc_policy,
    dmarcRua: row.dmarc_rua,
    catchAllAddress: row.catch_all_address || '',
    status: safeJson(row.status_json, {}),
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

function privateDomainRow(row) {
  const publicRow = publicDomainRow(row);
  return publicRow ? { ...publicRow, dkimPrivate: row.dkim_private } : null;
}

function publicInboundMailbox(row, { includeHash = false, includeSecret = false } = {}) {
  if (!row) return null;
  const passwordRecoverable = Boolean(row.password_secret && decryptSecret(row.password_secret));
  const expiresAt = row.expires_at || null;
  return {
    id: row.id,
    userId: row.user_id,
    domainId: row.domain_id,
    domain: row.domain || '',
    address: row.address,
    localPart: row.local_part,
    displayName: row.display_name,
    aliases: safeJson(row.aliases_json, []),
    forwardTo: safeJson(row.forward_to_json, []),
    keepForwarded: row.keep_forwarded !== 'false',
    quotaMb: row.quota_mb === null || row.quota_mb === undefined ? null : Number(row.quota_mb),
    passwordSet: Boolean(row.password_hash),
    passwordRecoverable,
    status: inboundMailboxStatus(row),
    expiresAt,
    temporary: Boolean(expiresAt),
    messageCount: Number(row.message_count || 0),
    unreadCount: Number(row.unread_count || 0),
    lastMessageAt: row.last_message_at || null,
    ...(includeHash ? { passwordHash: row.password_hash } : {}),
    ...(includeSecret ? { passwordSecret: row.password_secret } : {}),
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

function publicInboundMessage(row, { includeBody = false } = {}) {
  if (!row) return null;
  return {
    id: row.id,
    mailboxId: row.mailbox_id,
    userId: row.user_id,
    domainId: row.domain_id,
    domain: row.domain || '',
    folder: row.folder || 'INBOX',
    mailboxAddress: row.mailbox_address || '',
    sender: row.sender,
    recipients: safeJson(row.recipients_json, []),
    subject: row.subject,
    messageId: row.message_id,
    preview: row.preview,
    read: row.read_state === 'true',
    receivedAt: row.received_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    ...(includeBody ? {
      rawMessage: row.raw_message,
      textBody: row.text_body,
      htmlBody: row.html_body
    } : {})
  };
}

function publicSmtpCredential(row, { includeHash = false, includePassword = false, includeSecret = false } = {}) {
  if (!row) return null;
  const password = includePassword ? decryptSecret(row.password_secret) : '';
  const passwordRecoverable = Boolean(row.password_secret && (password || decryptSecret(row.password_secret)));
  return {
    id: row.id,
    userId: row.user_id,
    username: row.username,
    passwordSet: Boolean(row.password_hash),
    passwordRecoverable,
    ...(includePassword ? { password } : {}),
    ...(includeHash ? { passwordHash: row.password_hash } : {}),
    ...(includeSecret ? { passwordSecret: row.password_secret } : {}),
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

function publicSmtpRelay(row, { includePassword = false, includeSecret = false } = {}) {
  if (!row) return null;
  const password = includePassword ? decryptSecret(row.password_secret) : '';
  return {
    id: row.id,
    userId: row.user_id,
    name: row.name,
    host: row.host,
    port: Number(row.port || 587),
    secure: row.secure === 'true',
    username: row.username,
    passwordSet: Boolean(row.password_secret),
    helo: row.helo,
    isDefault: row.is_default === 'true',
    ...(includePassword ? { password } : {}),
    ...(includeSecret ? { passwordSecret: row.password_secret } : {}),
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

function publicApiToken(row) {
  if (!row) return null;
  return {
    id: row.id,
    userId: row.user_id,
    name: row.name,
    tokenPrefix: row.token_prefix,
    scopes: storedApiTokenScopes(row.scopes_json),
    expiresAt: row.expires_at || null,
    revokedAt: row.revoked_at || null,
    revokedReason: row.revoked_reason || '',
    status: apiTokenStatus(row),
    lastUsedAt: row.last_used_at,
    createdAt: row.created_at
  };
}

function getAccountTokenRow(id) {
  return requireDb().prepare('SELECT * FROM account_tokens WHERE id = ?').get(id);
}

function publicAccountToken(row) {
  if (!row) return null;
  return {
    id: row.id,
    userId: row.user_id,
    purpose: row.purpose,
    expiresAt: row.expires_at,
    usedAt: row.used_at,
    createdAt: row.created_at
  };
}

function publicDnsCredential(row) {
  if (!row) return null;
  return {
    id: row.id,
    userId: row.user_id,
    name: row.name,
    provider: row.provider,
    zoneName: row.zone_name,
    defaultTtl: row.default_ttl,
    credentialSet: Boolean(row.credentials_secret),
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

function publicSendEvent(row) {
  if (!row) return null;
  return {
    id: row.id,
    userId: row.user_id,
    domainId: row.domain_id,
    smtpRelayId: row.smtp_relay_id,
    domain: row.domain,
    sender: row.sender,
    recipients: safeJson(row.recipients, []),
    subject: row.subject,
    status: row.status,
    detail: row.detail,
    queueId: row.queue_id,
    deliveryLog: safeJson(row.delivery_log_json, []),
    deliveryAttempts: safeJson(row.delivery_attempts_json, []),
    tracking: {
      enabled: row.tracking_opens === 'true' || row.tracking_clicks === 'true',
      opens: row.tracking_opens === 'true',
      clicks: row.tracking_clicks === 'true',
      messageLevel: safeJson(row.recipients, []).length > 1
    },
    deliveredAt: row.delivered_at,
    createdAt: row.created_at
  };
}

function publicTrackingLink(row) {
  if (!row) return null;
  return {
    id: row.id,
    sendEventId: row.send_event_id,
    userId: row.user_id,
    domainId: row.domain_id,
    domain: row.domain || '',
    sender: row.sender,
    recipients: safeJson(row.recipients, []),
    subject: row.subject,
    status: row.status,
    trackingClicks: row.tracking_clicks === 'true',
    targetCiphertext: row.target_ciphertext,
    targetFingerprint: row.target_fingerprint,
    targetOrigin: row.target_origin,
    createdAt: row.created_at
  };
}

function listTrackingEventsForSendEvent(sendEventId, limit = 500) {
  return requireDb()
    .prepare(`
      SELECT recent.*, tl.target_origin
      FROM (
        SELECT *
        FROM tracking_events
        WHERE send_event_id = ?
        ORDER BY occurred_at DESC, id DESC
        LIMIT ?
      ) recent
      LEFT JOIN tracking_links tl ON tl.id = recent.tracking_link_id
      ORDER BY recent.occurred_at ASC, recent.id ASC
    `)
    .all(sendEventId, limit)
    .map(publicTrackingEvent);
}

function listTrackingAggregates(sendEventIds) {
  const ids = [...new Set(sendEventIds.map(Number).filter(Number.isInteger))];
  if (!ids.length) return new Map();
  const placeholders = ids.map(() => '?').join(', ');
  const rows = requireDb()
    .prepare(`
      SELECT
        send_event_id,
        COUNT(*) AS event_count,
        SUM(CASE WHEN event_type = 'open' AND source != 'scanner' THEN 1 ELSE 0 END) AS total_opens,
        SUM(CASE WHEN event_type = 'click' AND source = 'direct' THEN 1 ELSE 0 END) AS total_clicks,
        SUM(CASE WHEN event_type = 'open' AND source = 'proxy' THEN 1 ELSE 0 END) AS proxy_opens,
        SUM(CASE WHEN source = 'scanner' THEN 1 ELSE 0 END) AS scanner_events,
        MIN(CASE
          WHEN (event_type = 'open' AND source != 'scanner') OR (event_type = 'click' AND source = 'direct')
          THEN occurred_at END
        ) AS first_opened_at,
        MAX(CASE
          WHEN (event_type = 'open' AND source != 'scanner') OR (event_type = 'click' AND source = 'direct')
          THEN occurred_at END
        ) AS last_opened_at,
        MIN(CASE WHEN event_type = 'click' AND source = 'direct' THEN occurred_at END) AS first_clicked_at,
        MAX(CASE WHEN event_type = 'click' AND source = 'direct' THEN occurred_at END) AS last_clicked_at
      FROM tracking_events
      WHERE send_event_id IN (${placeholders})
      GROUP BY send_event_id
    `)
    .all(...ids);
  return new Map(rows.map((row) => {
    const totalOpens = Number(row.total_opens || 0);
    const totalClicks = Number(row.total_clicks || 0);
    return [row.send_event_id, {
      eventCount: Number(row.event_count || 0),
      summary: {
        totalOpens,
        totalClicks,
        uniqueOpen: totalOpens > 0 || totalClicks > 0,
        uniqueClick: totalClicks > 0,
        proxyOpens: Number(row.proxy_opens || 0),
        scannerEvents: Number(row.scanner_events || 0),
        firstOpenedAt: row.first_opened_at || null,
        lastOpenedAt: row.last_opened_at || null,
        firstClickedAt: row.first_clicked_at || null,
        lastClickedAt: row.last_clicked_at || null
      }
    }];
  }));
}

function emptyTrackingSummary() {
  return {
    totalOpens: 0,
    totalClicks: 0,
    uniqueOpen: false,
    uniqueClick: false,
    proxyOpens: 0,
    scannerEvents: 0,
    firstOpenedAt: null,
    lastOpenedAt: null,
    firstClickedAt: null,
    lastClickedAt: null
  };
}

function countTrackingLinksForSendEvent(sendEventId) {
  return Number(requireDb().prepare('SELECT COUNT(*) AS total FROM tracking_links WHERE send_event_id = ?').get(sendEventId)?.total || 0);
}

function listTrackingLinksForSendEvent(sendEventId, trackingSecret, limit = 200) {
  return requireDb()
    .prepare(`
      SELECT
        tl.*,
        SUM(CASE WHEN te.event_type = 'click' AND te.source = 'direct' THEN 1 ELSE 0 END) AS clicks,
        MIN(CASE WHEN te.event_type = 'click' AND te.source = 'direct' THEN te.occurred_at END) AS first_clicked_at,
        MAX(CASE WHEN te.event_type = 'click' AND te.source = 'direct' THEN te.occurred_at END) AS last_clicked_at
      FROM tracking_links tl
      LEFT JOIN tracking_events te ON te.tracking_link_id = tl.id
      WHERE tl.send_event_id = ?
      GROUP BY tl.id
      ORDER BY clicks DESC, last_clicked_at DESC, tl.id ASC
      LIMIT ?
    `)
    .all(sendEventId, limit)
    .map((row) => ({
      id: row.id,
      target: decryptTrackingTargetForOwner(row.target_ciphertext, row.target_origin, trackingSecret),
      targetOrigin: row.target_origin,
      clicks: Number(row.clicks || 0),
      firstClickedAt: row.first_clicked_at,
      lastClickedAt: row.last_clicked_at
    }));
}

function publicTrackingEvent(row) {
  if (!row) return null;
  return {
    id: row.id,
    sendEventId: row.send_event_id,
    trackingLinkId: row.tracking_link_id,
    eventType: row.event_type,
    source: row.source,
    occurredAt: row.occurred_at,
    userAgent: row.user_agent,
    targetOrigin: row.target_origin || ''
  };
}

function publicAuditLog(row) {
  if (!row) return null;
  return {
    id: row.id,
    actorUserId: row.actor_user_id,
    action: row.action,
    targetType: row.target_type,
    targetId: row.target_id,
    targetUserId: row.target_user_id,
    summary: safeJson(row.summary_json, {}),
    createdAt: row.created_at
  };
}

function getWebhookRow(id, userId) {
  return requireDb()
    .prepare('SELECT * FROM webhooks WHERE id = ? AND user_id = ?')
    .get(id, userId);
}

function publicWebhook(row) {
  if (!row) return null;
  return {
    id: row.id,
    userId: row.user_id,
    domainId: row.domain_id ?? null,
    name: row.name,
    url: row.url,
    secretPrefix: row.secret_prefix,
    events: parseWebhookEventsJson(row.events_json),
    enabled: row.enabled === 'true' || row.enabled === true || row.enabled === 1,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

function publicWebhookDelivery(row) {
  if (!row) return null;
  return {
    id: row.id,
    webhookId: row.webhook_id,
    userId: row.user_id,
    sendEventId: row.send_event_id,
    eventType: row.event_type,
    payloadJson: row.payload_json,
    status: row.status,
    attemptCount: Number(row.attempt_count || 0),
    nextAttemptAt: row.next_attempt_at,
    lastAttemptAt: row.last_attempt_at,
    responseStatus: row.response_status ?? null,
    responseBodyPreview: row.response_body_preview || '',
    error: row.error || '',
    createdAt: row.created_at
  };
}

function listWebhookRowsForResolve(userId, domainId) {
  const rows = domainId == null
    ? requireDb()
      .prepare('SELECT * FROM webhooks WHERE user_id = ? AND domain_id IS NULL')
      .all(userId)
    : requireDb()
      .prepare('SELECT * FROM webhooks WHERE user_id = ? AND domain_id = ?')
      .all(userId, domainId);
  return rows.map((row) => ({
    id: row.id,
    domainId: row.domain_id ?? null,
    enabled: row.enabled === 'true' || row.enabled === true || row.enabled === 1,
    events: parseWebhookEventsJson(row.events_json)
  }));
}

function normalizeWebhookDomainId(userId, domainId) {
  if (domainId == null || domainId === '') return null;
  const id = Number(domainId);
  if (!Number.isInteger(id) || id <= 0) throw new Error('域名不存在。');
  const domain = requireDb()
    .prepare('SELECT id FROM domains WHERE id = ? AND user_id = ?')
    .get(id, userId);
  if (!domain) throw new Error('域名不存在。');
  return id;
}

function generateWebhookSecret() {
  return `whsec_${crypto.randomBytes(24).toString('base64url')}`;
}

function resolveSendEventDomainName(sendEvent) {
  if (sendEvent?.domain) return String(sendEvent.domain);
  if (sendEvent?.domainId == null) return '';
  const row = requireDb()
    .prepare('SELECT domain FROM domains WHERE id = ?')
    .get(sendEvent.domainId);
  return row?.domain || '';
}

function truncateWebhookBodyPreview(value, maxLength = 2048) {
  const text = String(value ?? '');
  if (text.length <= maxLength) return text;
  return text.slice(0, maxLength);
}

function normalizeUsername(value) {
  const username = String(value || '').trim().toLowerCase();
  return /^[a-z0-9][a-z0-9_.-]{2,31}$/.test(username) ? username : '';
}

function normalizeUserStatus(value) {
  const status = String(value || '').trim();
  if (!USER_STATUSES.has(status)) throw new Error('用户状态不正确。');
  return status;
}

function normalizeAccountTokenPurpose(value) {
  const purpose = String(value || '').trim();
  if (!purpose) throw new Error('账号令牌用途不能为空。');
  return purpose;
}

function normalizeEmail(value) {
  const email = String(value || '').trim().toLowerCase();
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ? email : '';
}

function normalizeInboundAddress(value) {
  const email = normalizeEmail(value);
  if (!email) return '';
  const [localPart, domain] = email.split('@');
  if (!localPart || !domain) return '';
  return `${localPart}@${domain}`;
}

function normalizeInboundFolder(value, fallback = '') {
  const raw = String(value || fallback || '').trim().replace(/^"|"$/g, '').replace(/\\/g, '/');
  if (!raw || /[\r\n\u0000]/.test(raw)) return '';
  if (raw.toUpperCase() === 'INBOX') return 'INBOX';
  const standard = STANDARD_INBOUND_FOLDERS.find((folder) => folder.toLowerCase() === raw.toLowerCase());
  if (standard) return standard;
  return raw
    .split('/')
    .map((part) => part.trim())
    .filter(Boolean)
    .join('/');
}

function isStandardInboundFolder(value) {
  const clean = normalizeInboundFolder(value);
  return STANDARD_INBOUND_FOLDERS.some((folder) => folder === clean);
}

function normalizeCatchAllAddress(value) {
  const clean = String(value || '').trim().toLowerCase();
  if (!clean) return '';
  if (clean === '/dev/null') return clean;
  return normalizeInboundAddress(clean);
}

function normalizeInboundMailboxStatus(value) {
  const clean = String(value || '').trim().toLowerCase();
  if (['active', 'disabled'].includes(clean)) return clean;
  throw new Error('收信邮箱状态不正确。');
}

function normalizeInboundMailboxExpiresAt(value) {
  if (value === null || value === undefined || value === '') return null;
  const timestamp = Date.parse(String(value));
  if (!Number.isFinite(timestamp) || timestamp <= Date.now()) throw new Error('临时邮箱到期时间不正确。');
  return new Date(timestamp).toISOString();
}

function inboundMailboxStatus(row) {
  if (!row) return 'disabled';
  const expiresAt = String(row.expires_at || '');
  if (expiresAt && Date.parse(expiresAt) <= Date.now()) return 'expired';
  return row.status;
}

function normalizeApiTokenName(value) {
  const name = String(value || '').trim();
  if (!name) throw new Error('API Token 名称不能为空。');
  if (name.length > 100) throw new Error('API Token 名称不能超过 100 个字符。');
  return name;
}

function normalizeApiTokenScopes(value) {
  const candidates = value === undefined ? defaultApiTokenScopes : (Array.isArray(value) ? value : [value]);
  const scopes = [...new Set(candidates.map((item) => String(item || '').trim()).filter(Boolean))];
  if (!scopes.length || scopes.some((scope) => !API_TOKEN_SCOPES.has(scope))) {
    throw new Error('API Token 权限范围不正确。');
  }
  return scopes;
}

function storedApiTokenScopes(value) {
  try {
    const parsed = JSON.parse(value || '');
    const scopes = Array.isArray(parsed) ? parsed.filter((scope) => API_TOKEN_SCOPES.has(scope)) : [];
    return scopes.length ? scopes : [...defaultApiTokenScopes];
  } catch {
    return [...defaultApiTokenScopes];
  }
}

function normalizeApiTokenExpiresAt(value) {
  if (value === null || value === undefined || value === '') return null;
  const timestamp = Date.parse(String(value));
  if (!Number.isFinite(timestamp) || timestamp <= Date.now()) throw new Error('API Token 到期时间不正确。');
  return new Date(timestamp).toISOString();
}

function apiTokenStatus(row) {
  if (row?.revoked_at) return 'revoked';
  const expiresAt = String(row?.expires_at || '');
  if (expiresAt && Date.parse(expiresAt) <= Date.now()) return 'expired';
  return 'active';
}

function normalizeMailboxAliases(values, domain, ownLocalPart) {
  const list = Array.isArray(values)
    ? values
    : String(values || '').split(/[\s,;]+/);
  const cleanDomain = String(domain || '').toLowerCase();
  const own = String(ownLocalPart || '').toLowerCase();
  const aliases = [];
  for (const value of list) {
    const raw = String(value || '').trim().toLowerCase();
    if (!raw) continue;
    const localPart = raw.includes('@')
      ? (normalizeInboundAddress(raw).endsWith(`@${cleanDomain}`) ? normalizeInboundAddress(raw).split('@')[0] : '')
      : raw;
    if (!localPart || localPart === own || !/^[^@\s]+$/.test(localPart)) continue;
    if (!aliases.includes(localPart)) aliases.push(localPart);
  }
  return aliases;
}

function normalizeQuotaMb(value) {
  if (value === null || value === undefined || value === '') return null;
  const quota = Number(value);
  if (!Number.isFinite(quota) || quota < 0) return null;
  return Math.floor(quota);
}

function normalizeRecipientList(values) {
  const list = Array.isArray(values) ? values : [values];
  return [...new Set(list.flatMap((value) => String(value || '').split(/[\s,;]+/)).map(normalizeEmail).filter(Boolean))];
}

function getInboundMailboxByAliasAddress(address) {
  const cleanAddress = normalizeInboundAddress(address);
  if (!cleanAddress) return null;
  const [localPart, domainName] = cleanAddress.split('@');
  const rows = requireDb()
    .prepare(`
      SELECT m.*, d.domain, 0 AS message_count, 0 AS unread_count, NULL AS last_message_at
      FROM inbound_mailboxes m
      JOIN domains d ON d.id = m.domain_id
      JOIN users u ON u.id = m.user_id
      WHERE d.domain = ?
        AND m.status = 'active'
        AND m.deleted_at IS NULL
        AND (m.expires_at IS NULL OR m.expires_at = '' OR m.expires_at > ?)
        AND u.status = 'active'
    `)
    .all(domainName, now());
  const row = rows.find((item) => safeJson(item.aliases_json, []).includes(localPart));
  return publicInboundMailbox(row);
}

function inboundRouteForMailbox(recipient, mailbox, meta = {}) {
  return {
    recipient,
    domainId: mailbox.domainId,
    userId: mailbox.userId,
    mailbox,
    forwardTo: normalizeRecipientList(mailbox.forwardTo)
      .filter((target) => target !== mailbox.address && target !== recipient),
    keepForwarded: mailbox.keepForwarded,
    drop: false,
    catchAll: Boolean(meta.catchAll),
    alias: Boolean(meta.alias)
  };
}

function inboundPreview(value) {
  return String(value || '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 240);
}

function htmlToText(value) {
  return String(value || '')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/g, "'");
}

function normalizePort(value, fallback) {
  const port = Number(value);
  return Number.isInteger(port) && port > 0 && port <= 65535 ? port : fallback;
}

function boolString(value) {
  return value === true || String(value).toLowerCase() === 'true' ? 'true' : 'false';
}

function normalizeTrackingSource(value) {
  const source = String(value || '').toLowerCase();
  return ['direct', 'proxy', 'scanner'].includes(source) ? source : 'direct';
}

function normalizeIsoDate(value) {
  const date = new Date(value || Date.now());
  if (Number.isNaN(date.getTime())) throw new Error('Invalid tracking event time.');
  return date.toISOString();
}

function isQualifyingTrackingEvent(eventType, source) {
  return eventType === 'click' ? source === 'direct' : source !== 'scanner';
}

function normalizeProvider(value) {
  const provider = String(value || '').trim().toLowerCase();
  return ['cloudflare', 'aliyun', 'dnspod'].includes(provider) ? provider : '';
}

function pickCredentialFields(source) {
  const output = {};
  for (const key of ['apiToken', 'zoneId', 'accessKeyId', 'accessKeySecret', 'secretId', 'secretKey']) {
    if (source[key]) output[key] = String(source[key]).trim();
  }
  return output;
}

function clampTtl(value) {
  const ttl = Number(value || 600);
  if (!Number.isInteger(ttl) || ttl < 60) return 600;
  if (ttl > 86400) return 86400;
  return ttl;
}

function clampAnalyticsDays(value) {
  const days = Number(value || 7);
  if (!Number.isInteger(days) || days < 7) return 7;
  if (days > 90) return 90;
  return days;
}

function buildDayBuckets(days) {
  const buckets = new Map();
  const cursor = new Date();
  cursor.setUTCHours(0, 0, 0, 0);
  cursor.setUTCDate(cursor.getUTCDate() - (days - 1));
  for (let index = 0; index < days; index += 1) {
    const date = new Date(cursor);
    date.setUTCDate(cursor.getUTCDate() + index);
    const day = date.toISOString().slice(0, 10);
    buckets.set(day, {
      day,
      total: 0,
      queued: 0,
      failed: 0,
      accepted: 0,
      delivered: 0,
      pending: 0,
      terminalFailed: 0,
      recipients: 0
    });
  }
  return buckets;
}

function percent(part, total) {
  return total ? Math.round((Number(part || 0) / total) * 1000) / 10 : 0;
}

function safeJson(value, fallback) {
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function sanitizeAuditSummary(value, parentKey = '') {
  if (Array.isArray(value)) return value.map((item) => sanitizeAuditSummary(item, parentKey));
  if (!value || typeof value !== 'object') return value;
  const hasSensitiveDescriptor = hasSensitiveAuditDescriptor(value);
  const output = {};
  for (const [key, child] of Object.entries(value)) {
    if (auditSecretKeyPattern.test(key) && !isSafeAuditStateKey(key, child, parentKey)) continue;
    if (hasSensitiveDescriptor && auditValueLikeKeyPattern.test(key)) continue;
    output[key] = sanitizeAuditSummary(child, key);
  }
  return output;
}

function isSafeAuditStateKey(key, value, parentKey) {
  return (key === 'passwordSet' && typeof value === 'boolean') ||
    (parentKey === 'counts' && typeof value === 'number');
}

function hasSensitiveAuditDescriptor(value) {
  return Object.entries(value).some(([key, child]) => (
    auditDescriptorKeyPattern.test(key) && isSensitiveAuditDescriptorValue(child)
  )) || Object.entries(value).some(([key, child]) => (
    auditDescriptorWrapperKeyPattern.test(key) && hasDirectSensitiveAuditDescriptor(child)
  ));
}

function hasDirectSensitiveAuditDescriptor(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  return Object.entries(value).some(([key, child]) => (
    auditDescriptorKeyPattern.test(key) && isSensitiveAuditDescriptorValue(child)
  ));
}

function isSensitiveAuditDescriptorValue(value) {
  if (Array.isArray(value)) return value.some(isSensitiveAuditDescriptorValue);
  if (value && typeof value === 'object') return Object.values(value).some(isSensitiveAuditDescriptorValue);
  return auditDescriptorValuePattern.test(String(value ?? ''));
}

function addAuditFilter(where, params, column, value) {
  if (value === undefined) return;
  if (value === null) {
    where.push(`${column} IS NULL`);
    return;
  }
  where.push(`${column} = ?`);
  params.push(value);
}

function addAuditDateFilter(where, params, column, operator, value) {
  if (value === undefined || value === null || value === '') return;
  where.push(`${column} ${operator} ?`);
  params.push(value);
}

function normalizeQueueId(value) {
  return String(value || '').trim().toUpperCase();
}

function extractQueueIdFromText(value) {
  return String(value || '').match(/\bqueued as\s+([A-Z0-9]{5,})\b/i)?.[1]?.toUpperCase() || '';
}

function normalizeDeliveryAttempt(attempt, queueId) {
  return {
    at: attempt?.at || now(),
    source: attempt?.source || 'postfix',
    queueId,
    recipient: String(attempt?.recipient || '').toLowerCase(),
    relay: String(attempt?.relay || ''),
    dsn: String(attempt?.dsn || ''),
    status: String(attempt?.status || 'unknown').toLowerCase(),
    response: String(attempt?.response || ''),
    raw: String(attempt?.raw || '')
  };
}

function deliveryAttemptKey(attempt) {
  return attempt.raw || [
    attempt.queueId,
    attempt.recipient,
    attempt.status,
    attempt.dsn,
    attempt.response
  ].join('|');
}

function deliveryStatusForEvent(recipients, attempts, currentStatus) {
  const byRecipient = new Map();
  for (const attempt of attempts) {
    if (attempt.recipient) byRecipient.set(String(attempt.recipient).toLowerCase(), attempt.status);
  }
  const normalizedRecipients = recipients.map((recipient) => String(recipient || '').toLowerCase()).filter(Boolean);
  const statuses = normalizedRecipients.map((recipient) => byRecipient.get(recipient)).filter(Boolean);
  if (normalizedRecipients.length && statuses.length === normalizedRecipients.length && statuses.every((status) => status === 'sent')) {
    return 'sent';
  }
  if (statuses.includes('deferred')) return 'deferred';
  if (statuses.includes('bounced')) return 'bounced';
  return currentStatus || attempts.at(-1)?.status || 'queued';
}

function deliveryAttemptDetail(attempt) {
  const parts = [
    attempt.status,
    attempt.recipient ? `to ${attempt.recipient}` : '',
    attempt.relay ? `via ${attempt.relay}` : '',
    attempt.dsn ? `dsn=${attempt.dsn}` : ''
  ].filter(Boolean);
  return `${parts.join(' ')}${attempt.response ? `; ${attempt.response}` : ''}`;
}

function now() {
  return new Date().toISOString();
}

function tokenHash(token) {
  return crypto.createHash('sha256').update(String(token || '')).digest('hex');
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return `scrypt$${salt}$${hash}`;
}

function verifyPassword(password, stored) {
  const [scheme, salt, hash] = String(stored || '').split('$');
  if (scheme !== 'scrypt' || !salt || !hash) return false;
  const actual = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return safeEqual(actual, hash);
}

function encryptSecret(value) {
  if (!value) return '';
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(String(value), 'utf8'), cipher.final()]);
  return [
    'v1',
    iv.toString('base64url'),
    cipher.getAuthTag().toString('base64url'),
    encrypted.toString('base64url')
  ].join('$');
}

function decryptSecret(secret) {
  const [version, ivRaw, tagRaw, encryptedRaw] = String(secret || '').split('$');
  if (version !== 'v1' || !ivRaw || !tagRaw || !encryptedRaw) return '';
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey(), Buffer.from(ivRaw, 'base64url'));
    decipher.setAuthTag(Buffer.from(tagRaw, 'base64url'));
    return Buffer.concat([
      decipher.update(Buffer.from(encryptedRaw, 'base64url')),
      decipher.final()
    ]).toString('utf8');
  } catch {
    return '';
  }
}

function encryptionKey() {
  return crypto
    .createHash('sha256')
    .update(secretKey || 'mailhub-local-secret')
    .digest();
}

function safeEqual(actual, expected) {
  const a = Buffer.from(String(actual || ''));
  const b = Buffer.from(String(expected || ''));
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}
