import { mkdirSync } from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { dkimPublicFromPrivateKey } from './dkim.js';
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
const auditSecretKeyPattern = /password|secret|token|key|credential|dkim[_-]?private|authorization/i;
const auditDescriptorKeyPattern = /^(field|name|path|key|header)$/i;
const auditDescriptorValuePattern = /password|secret|token|key|credential|dkim[_-]?private|authorization/i;
const auditDescriptorWrapperKeyPattern = /^(change|context|descriptor|meta)$/i;
const auditValueLikeKeyPattern = /^(value|from|to|old|new|old_?value|new_?value|before|after)$/i;
const maxAccountTokenTtlMinutes = 7 * 24 * 60;

export function initDatabase(dataDir, secret = '') {
  secretKey = String(secret || process.env.SESSION_SECRET || process.env.API_TOKEN || process.env.ADMIN_PASSWORD || '');
  mkdirSync(dataDir, { recursive: true });
  db = new DatabaseSync(path.join(dataDir, 'mailhub.sqlite'));
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
      created_at TEXT NOT NULL,
      FOREIGN KEY(domain_id) REFERENCES domains(id) ON DELETE SET NULL
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

    CREATE TABLE IF NOT EXISTS api_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      token_prefix TEXT NOT NULL,
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
  `);
  ensureColumn('domains', 'user_id', 'INTEGER');
  ensureColumn('domains', 'dns_credential_id', 'INTEGER');
  ensureColumn('domains', 'smtp_relay_id', 'INTEGER');
  ensureColumn('send_events', 'user_id', 'INTEGER');
  ensureColumn('send_events', 'smtp_relay_id', 'INTEGER');
  ensureColumn('send_events', 'queue_id', "TEXT NOT NULL DEFAULT ''");
  ensureColumn('send_events', 'delivery_log_json', "TEXT NOT NULL DEFAULT '[]'");
  ensureColumn('send_events', 'delivery_attempts_json', "TEXT NOT NULL DEFAULT '[]'");
  ensureColumn('send_events', 'delivered_at', 'TEXT');
  migrateSmtpCredentialsToMultiplePerUser();
  ensureColumn('smtp_credentials', 'password_secret', "TEXT NOT NULL DEFAULT ''");
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_domains_user_id ON domains(user_id);
    CREATE INDEX IF NOT EXISTS idx_domains_smtp_relay_id ON domains(smtp_relay_id);
    CREATE INDEX IF NOT EXISTS idx_events_user_id ON send_events(user_id);
    CREATE INDEX IF NOT EXISTS idx_events_smtp_relay_id ON send_events(smtp_relay_id);
    CREATE INDEX IF NOT EXISTS idx_events_queue_id ON send_events(queue_id);
    CREATE INDEX IF NOT EXISTS idx_smtp_credentials_user_id ON smtp_credentials(user_id);
    CREATE INDEX IF NOT EXISTS idx_smtp_relays_user_id ON smtp_relays(user_id);
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
  const sendEventCounts = new Map(
    requireDb()
      .prepare('SELECT user_id, COUNT(*) AS count FROM send_events GROUP BY user_id')
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
        dnsCredentialId: domain.dns_credential_id || null
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
    const counts = {
      domains: options.transferDomains === false ? 0 : moveRows('domains', sourceId, targetId),
      dnsCredentials: options.transferDnsCredentials === false ? 0 : moveRows('dns_credentials', sourceId, targetId),
      apiTokens: options.transferApiTokens === false ? 0 : moveRows('api_tokens', sourceId, targetId),
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
    updatedAt: now()
  };
  requireDb()
    .prepare(`
      UPDATE domains
      SET selector = ?, dns_credential_id = ?, smtp_relay_id = ?, sender_host = ?, sending_ip = ?, spf_extra = ?,
          dmarc_policy = ?, dmarc_rua = ?, updated_at = ?
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

export function logSendEvent(event) {
  const queueId = normalizeQueueId(event.queueId || extractQueueIdFromText(event.detail));
  const recipients = Array.isArray(event.recipients) ? event.recipients : [];
  const result = requireDb()
    .prepare(`
      INSERT INTO send_events (
        user_id, domain_id, smtp_relay_id, sender, recipients, subject, status, detail, queue_id,
        delivery_log_json, delivery_attempts_json, delivered_at, created_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
    .run(
      event.userId ?? null,
      event.domainId ?? null,
      event.smtpRelayId ?? null,
      event.sender,
      JSON.stringify(recipients),
      event.subject,
      event.status,
      event.detail ?? '',
      queueId,
      JSON.stringify(Array.isArray(event.deliveryLog) ? event.deliveryLog : []),
      JSON.stringify(Array.isArray(event.deliveryAttempts) ? event.deliveryAttempts : []),
      event.deliveredAt ?? null,
      now()
    );
  const id = result.lastInsertRowid;
  if (isTerminalWebhookStatus(event.status)) {
    try {
      enqueueWebhookDeliveries({
        id,
        userId: event.userId,
        domainId: event.domainId ?? null,
        domain: event.domain,
        status: event.status,
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
  return requireDb()
    .prepare(`
      SELECT e.*, d.domain
      FROM send_events e
      LEFT JOIN domains d ON d.id = e.domain_id
      WHERE e.user_id = ?
      ORDER BY e.created_at DESC
      LIMIT ?
    `)
    .all(userId, limit)
    .map(publicSendEvent);
}

export function getSendEvent(userId, eventId) {
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
  return {
    ...event,
    webhookDeliveries: listWebhookDeliveries(userId, {
      sendEventId: event.id,
      limit: 50
    })
  };
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
 * Enqueue pending webhook deliveries for a terminal send event.
 * Idempotent on (webhook_id, send_event_id, event_type).
 */
export function enqueueWebhookDeliveries(sendEvent) {
  if (!sendEvent?.userId) return [];
  if (!isTerminalWebhookStatus(sendEvent.status)) return [];

  const eventType = sendEvent.status;
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
    status: eventType,
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
  const database = requireDb();
  for (const webhook of targets) {
    database.exec('BEGIN');
    try {
      const existing = database
        .prepare(`
          SELECT id FROM webhook_deliveries
          WHERE webhook_id = ? AND send_event_id = ? AND event_type = ?
        `)
        .get(webhook.id, normalizedEvent.id, eventType);
      if (existing) {
        database.exec('COMMIT');
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
        database.exec('ROLLBACK');
        continue;
      }
      const deliveryId = insert.lastInsertRowid;
      const payload = buildWebhookPayload({
        deliveryId,
        eventType: externalType,
        createdAt,
        sendEvent: normalizedEvent,
        test: false
      });
      database
        .prepare('UPDATE webhook_deliveries SET payload_json = ? WHERE id = ?')
        .run(JSON.stringify(payload), deliveryId);
      database.exec('COMMIT');
      created.push(publicWebhookDelivery(
        database.prepare('SELECT * FROM webhook_deliveries WHERE id = ?').get(deliveryId)
      ));
    } catch (error) {
      try {
        database.exec('ROLLBACK');
      } catch {
        // ignore rollback errors when no transaction is open
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

export function getSendAnalytics(userId, { days = 7 } = {}) {
  const windowDays = clampAnalyticsDays(days);
  const since = new Date();
  since.setUTCHours(0, 0, 0, 0);
  since.setUTCDate(since.getUTCDate() - (windowDays - 1));
  const rows = requireDb()
    .prepare(`
      SELECT e.*, d.domain
      FROM send_events e
      LEFT JOIN domains d ON d.id = e.domain_id
      WHERE e.user_id = ? AND e.created_at >= ?
      ORDER BY e.created_at ASC
      LIMIT 5000
    `)
    .all(userId, since.toISOString());
  const domains = listDomains(userId);
  const dayBuckets = buildDayBuckets(windowDays);
  const byStatus = {};
  const byDomain = new Map();
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
  let recipients = 0;
  let queued = 0;
  let failed = 0;
  let accepted = 0;
  let delivered = 0;
  let pending = 0;
  let deferred = 0;
  let bounced = 0;
  let terminalFailed = 0;
  let today = 0;
  let last7Days = 0;
  const failureReasons = new Map();
  const todayKey = new Date().toISOString().slice(0, 10);
  const weekStart = new Date();
  weekStart.setUTCHours(0, 0, 0, 0);
  weekStart.setUTCDate(weekStart.getUTCDate() - 6);

  for (const row of rows) {
    const status = row.status || 'unknown';
    const recipientList = safeJson(row.recipients, []);
    const recipientCount = Array.isArray(recipientList) ? recipientList.length : 0;
    const domainName = row.domain || (String(row.sender || '').split('@')[1] || 'unknown');
    const createdAt = new Date(row.created_at);
    const dayKey = row.created_at.slice(0, 10);
    const hour = Number.isInteger(createdAt.getUTCHours()) ? createdAt.getUTCHours() : 0;
    const isQueued = ['queued', 'sent'].includes(status);
    const classification = classifySendEvent(row);

    recipients += recipientCount;
    queued += isQueued ? 1 : 0;
    failed += isQueued ? 0 : 1;
    accepted += classification.accepted ? 1 : 0;
    delivered += classification.delivered ? 1 : 0;
    pending += classification.pending ? 1 : 0;
    deferred += classification.deferred ? 1 : 0;
    bounced += classification.bounced ? 1 : 0;
    terminalFailed += classification.terminalFailed ? 1 : 0;
    today += dayKey === todayKey ? 1 : 0;
    last7Days += createdAt >= weekStart ? 1 : 0;
    byStatus[status] = (byStatus[status] || 0) + 1;
    if (isDeliveryFailureStatus(status)) addFailureReason(failureReasons, row);

    if (dayBuckets.has(dayKey)) {
      const bucket = dayBuckets.get(dayKey);
      bucket.total += 1;
      bucket.queued += isQueued ? 1 : 0;
      bucket.failed += isQueued ? 0 : 1;
      bucket.accepted += classification.accepted ? 1 : 0;
      bucket.delivered += classification.delivered ? 1 : 0;
      bucket.pending += classification.pending ? 1 : 0;
      bucket.terminalFailed += classification.terminalFailed ? 1 : 0;
      bucket.recipients += recipientCount;
    }

    const domainBucket = byDomain.get(domainName) || {
      domain: domainName,
      total: 0,
      queued: 0,
      failed: 0,
      accepted: 0,
      delivered: 0,
      pending: 0,
      terminalFailed: 0,
      recipients: 0
    };
    domainBucket.total += 1;
    domainBucket.queued += isQueued ? 1 : 0;
    domainBucket.failed += isQueued ? 0 : 1;
    domainBucket.accepted += classification.accepted ? 1 : 0;
    domainBucket.delivered += classification.delivered ? 1 : 0;
    domainBucket.pending += classification.pending ? 1 : 0;
    domainBucket.terminalFailed += classification.terminalFailed ? 1 : 0;
    domainBucket.recipients += recipientCount;
    byDomain.set(domainName, domainBucket);

    hourly[hour].total += 1;
    hourly[hour].queued += isQueued ? 1 : 0;
    hourly[hour].failed += isQueued ? 0 : 1;
    hourly[hour].accepted += classification.accepted ? 1 : 0;
    hourly[hour].delivered += classification.delivered ? 1 : 0;
    hourly[hour].pending += classification.pending ? 1 : 0;
    hourly[hour].terminalFailed += classification.terminalFailed ? 1 : 0;
  }

  const recentFailures = [...rows]
    .reverse()
    .filter((row) => isDeliveryFailureStatus(row.status))
    .slice(0, 8)
    .map((row) => ({
      id: row.id,
      domain: row.domain || '',
      sender: row.sender,
      subject: row.subject,
      detail: row.detail,
      createdAt: row.created_at
    }));

  return {
    windowDays,
    summary: {
      total: rows.length,
      submitted: rows.length,
      queued,
      failed,
      accepted,
      delivered,
      pending,
      deferred,
      bounced,
      terminalFailed,
      recipients,
      today,
      last7Days,
      successRate: percent(queued, rows.length),
      acceptanceRate: percent(accepted, rows.length),
      deliveryRate: percent(delivered, rows.length),
      failureRate: percent(terminalFailed, rows.length),
      domains: domains.length,
      verifiedDomains: domains.filter((domain) => domain.status?.verified).length
    },
    deliveryFunnel: [
      { stage: 'submitted', total: rows.length, rate: percent(rows.length, rows.length) },
      { stage: 'accepted', total: accepted, rate: percent(accepted, rows.length) },
      { stage: 'delivered', total: delivered, rate: percent(delivered, rows.length) },
      { stage: 'pending', total: pending, rate: percent(pending, rows.length) },
      { stage: 'failed', total: terminalFailed, rate: percent(terminalFailed, rows.length) }
    ],
    byDay: [...dayBuckets.values()],
    byDomain: [...byDomain.values()].sort((a, b) => b.total - a.total).slice(0, 10),
    byStatus: Object.entries(byStatus).map(([status, total]) => ({ status, total })),
    hourly,
    failureReasons: [...failureReasons.values()]
      .sort((a, b) => b.total - a.total || String(b.lastSeenAt).localeCompare(String(a.lastSeenAt)))
      .slice(0, 10),
    recentFailures
  };
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
  const row = requireDb()
    .prepare(`
      SELECT c.*, u.id AS auth_user_id, u.username AS auth_username, u.email, u.role, u.status
      FROM smtp_credentials c
      JOIN users u ON u.id = c.user_id
      WHERE c.username = ?
    `)
    .get(String(username || '').trim());
  if (!row || row.status !== 'active' || !verifyPassword(password, row.password_hash)) return null;
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

export function createApiToken(userId, name) {
  const token = `mh_${crypto.randomBytes(32).toString('base64url')}`;
  const createdAt = now();
  const result = requireDb()
    .prepare(`
      INSERT INTO api_tokens (user_id, name, token_hash, token_prefix, created_at)
      VALUES (?, ?, ?, ?, ?)
    `)
    .run(userId, String(name || 'API Token').trim() || 'API Token', tokenHash(token), token.slice(0, 12), createdAt);
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

export function deleteApiToken(id, userId) {
  const result = requireDb().prepare('DELETE FROM api_tokens WHERE id = ? AND user_id = ?').run(id, userId);
  return result.changes > 0;
}

export function verifyApiToken(token) {
  const hash = tokenHash(token);
  const row = requireDb()
    .prepare(`
      SELECT t.*, u.id AS auth_user_id, u.username, u.email, u.role, u.status
      FROM api_tokens t
      JOIN users u ON u.id = t.user_id
      WHERE t.token_hash = ?
    `)
    .get(hash);
  if (!row || row.status !== 'active') return null;
  requireDb().prepare('UPDATE api_tokens SET last_used_at = ? WHERE id = ?').run(now(), row.id);
  return {
    id: row.auth_user_id,
    username: row.username,
    email: row.email,
    role: row.role,
    status: row.status
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
    'sendRequiresVerified'
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
    sendEventCount: countRows('send_events', userId),
    smtpCredential: getSmtpCredential(userId)
  };
}

function countRows(table, userId) {
  return Number(requireDb().prepare(`SELECT COUNT(*) AS count FROM ${mergeResourceTable(table)} WHERE user_id = ?`).get(userId).count || 0);
}

function moveRows(table, sourceUserId, targetUserId) {
  const result = requireDb()
    .prepare(`UPDATE ${mergeResourceTable(table)} SET user_id = ? WHERE user_id = ?`)
    .run(targetUserId, sourceUserId);
  return result.changes;
}

function mergeResourceTable(table) {
  if (!['domains', 'dns_credentials', 'api_tokens', 'send_events', 'smtp_credentials'].includes(table)) {
    throw new Error('资源类型不正确。');
  }
  return table;
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
    status: safeJson(row.status_json, {}),
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

function privateDomainRow(row) {
  const publicRow = publicDomainRow(row);
  return publicRow ? { ...publicRow, dkimPrivate: row.dkim_private } : null;
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
    deliveredAt: row.delivered_at,
    createdAt: row.created_at
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

function normalizePort(value, fallback) {
  const port = Number(value);
  return Number.isInteger(port) && port > 0 && port <= 65535 ? port : fallback;
}

function boolString(value) {
  return value === true || String(value).toLowerCase() === 'true' ? 'true' : 'false';
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

function classifySendEvent(row) {
  const status = String(row?.status || '').toLowerCase();
  const hasQueueId = Boolean(normalizeQueueId(row?.queue_id));
  const accepted = hasQueueId || ['queued', 'sent', 'deferred', 'bounced'].includes(status);
  return {
    status,
    accepted,
    delivered: status === 'sent',
    pending: status === 'queued' || status === 'deferred',
    deferred: status === 'deferred',
    bounced: status === 'bounced',
    terminalFailed: status === 'bounced' || status === 'failed'
  };
}

function normalizeFailureReason(row) {
  const detail = String(row?.detail || '').replace(/\s+/g, ' ').trim();
  return detail || String(row?.status || 'unknown failure');
}

function addFailureReason(map, row) {
  const reason = normalizeFailureReason(row);
  const status = String(row?.status || 'unknown').toLowerCase();
  const bucket = map.get(reason) || {
    reason,
    total: 0,
    statuses: {},
    lastSeenAt: row?.created_at || ''
  };
  bucket.total += 1;
  bucket.statuses[status] = (bucket.statuses[status] || 0) + 1;
  if (row?.created_at && row.created_at > bucket.lastSeenAt) bucket.lastSeenAt = row.created_at;
  map.set(reason, bucket);
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

function isDeliveryFailureStatus(status) {
  return ['deferred', 'bounced', 'failed'].includes(String(status || '').toLowerCase());
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
