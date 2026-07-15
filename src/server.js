import crypto from 'node:crypto';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath, domainToASCII } from 'node:url';
import {
  authenticateUser,
  authenticateApiToken,
  approveUser,
  claimLegacyData,
  createApiToken,
  createAccountToken,
  createDomain,
  createInboundMailbox,
  createSendEvent,
  createTrackingLink,
  createUserWithAccountToken,
  createWebhook,
  consumeAccountToken,
  deleteDnsCredential,
  deleteDomain,
  deleteSmtpCredential,
  deleteWebhook,
  enqueueWebhookTestDelivery,
  getAdminResourceInventory,
  getAdminUser,
  getDnsCredential,
  getDomain,
  getDomainByName,
  getApiToken,
  getInboundMessage,
  getSendEvent,
  getSendAnalytics,
  getSettings,
  getDefaultSmtpRelay,
  getSmtpRelay,
  getSmtpCredential,
  getSystemEmailSettings,
  getUser,
  getUserByLogin,
  initDatabase,
  invalidateAccountTokens,
  listApiTokens,
  listAuditLogs,
  listDnsCredentials,
  listDomains,
  listInboundMailboxes,
  listInboundMessages,
  listSendEvents,
  listSmtpCredentials,
  listSmtpRelays,
  listUsersWithResourceCounts,
  listWebhookDeliveries,
  listWebhooks,
  logAudit,
  logSendEvent,
  markInboundMessageRead,
  markUserEmailVerified,
  previewUserMerge,
  replayWebhookDelivery,
  rotateWebhookSecret,
  saveDnsCredential,
  saveDomainStatus,
  saveSettings,
  saveSmtpRelay,
  saveSmtpCredential,
  saveSystemEmailSettings,
  seedAdminUser,
  seedSmtpCredential,
  deleteSmtpRelay,
  transferApiTokens,
  transferDnsCredential,
  transferDomain,
  updateInboundMailbox,
  updateApiToken,
  updateDkim,
  updateDomain,
  updateUser,
  updateWebhook,
  executeUserMerge,
  finalizeSendEvent,
  findSendEventByTrackingToken,
  findTrackingLinkByToken,
  recordTrackingEvent,
  revokeApiToken,
  verifyUserCredentials
} from './db.js';
import { applyDnsSetup, testDnsCredential } from './dns-providers.js';
import { startDnsAutoChecker } from './dns-auto-checker.js';
import { startPostfixDeliveryTracker } from './delivery-tracker.js';
import { assertSafeWebhookUrl, startWebhookWorker } from './webhook-dispatcher.js';
import { buildDnsGuide, buildSystemDnsChecks } from './dns-guide.js';
import { createDkimKeyPair } from './dkim.js';
import {
  buildDeliverabilityHeaders,
  buildMessage,
  createFeedbackId,
  domainFromAddress,
  extractAddress,
  parseAddressList,
  resolveEnvelopeSender,
  sendViaSmtp,
  signMessageForDomain
} from './mailer.js';
import {
  parseMailboxAccessListeners,
  publicMailboxAccessListeners,
  startMailboxAccessServers
} from './mail-access.js';
import {
  parseSubmissionListeners,
  publicSubmissionListeners,
  startSubmissionServer
} from './submission.js';
import {
  buildPasswordResetEmail,
  buildVerificationEmail,
  sendSystemEmail
} from './system-mail.js';
import {
  classifyTrackingSource,
  createTrackingToken,
  decryptTrackingTarget,
  encryptTrackingTarget,
  hashTrackingClientIp,
  instrumentHtml,
  trackingTargetFingerprint,
  trackingReplayKey
} from './tracking.js';
import { startTrackingRetentionWorker } from './tracking-retention.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
loadDotEnv();
const fallbackSecret = crypto
  .createHash('sha256')
  .update(`${process.env.ADMIN_PASSWORD || 'change-this-admin-password'}:${process.env.API_TOKEN || ''}`)
  .digest('hex');

const envConfig = {
  port: Number(process.env.PORT || 3000),
  dataDir: process.env.DATA_DIR || path.join(process.cwd(), 'data'),
  adminUser: process.env.ADMIN_USER || 'admin',
  adminEmail: process.env.ADMIN_EMAIL || `${process.env.ADMIN_USER || 'admin'}@mailhub.local`,
  adminPassword: process.env.ADMIN_PASSWORD || 'change-this-admin-password',
  legacyApiToken: process.env.API_TOKEN || '',
  smtpHost: process.env.SMTP_HOST || '',
  smtpPort: Number(process.env.SMTP_PORT || 25),
  smtpSecure: String(process.env.SMTP_SECURE || '').toLowerCase() === 'true',
  smtpUser: process.env.SMTP_USERNAME || '',
  smtpPassword: process.env.SMTP_PASSWORD || '',
  smtpHelo: process.env.SMTP_HELO || process.env.MAIL_HOSTNAME || 'mailhub.local',
  postfixLogFile: process.env.POSTFIX_LOG_FILE || path.join(process.env.DATA_DIR || path.join(process.cwd(), 'data'), 'postfix-logs', 'mail.log'),
  postfixLogPollIntervalMs: Number(process.env.POSTFIX_LOG_POLL_INTERVAL_MS || 5000),
  deliveryTrackingEnabled: String(process.env.DELIVERY_TRACKING_ENABLED || 'true').toLowerCase() !== 'false',
  dnsAutoCheckEnabled: String(process.env.DNS_AUTO_CHECK_ENABLED || 'true').toLowerCase() !== 'false',
  dnsAutoCheckIntervalMs: Number(process.env.DNS_AUTO_CHECK_INTERVAL_MS || 60000),
  dnsAutoCheckLimit: Number(process.env.DNS_AUTO_CHECK_LIMIT || 25),
  webhookWorkerEnabled:
    String(process.env.WEBHOOK_WORKER_ENABLED || 'true').toLowerCase() !== 'false' &&
    String(process.env.WEBHOOK_WORKER_ENABLED || '') !== '0',
  webhookWorkerIntervalMs: Number(process.env.WEBHOOK_WORKER_INTERVAL_MS || 10000),
  webhookWorkerBatchSize: Number(process.env.WEBHOOK_WORKER_BATCH_SIZE || 3),
  submissionEnabled: String(process.env.SUBMISSION_ENABLED || 'true').toLowerCase() !== 'false',
  submissionHost: process.env.SUBMISSION_HOST || process.env.APP_BASE_URL?.replace(/^https?:\/\//, '') || 'localhost',
  submissionListeners: parseSubmissionListeners(process.env.SUBMISSION_PORTS),
  submissionUsername: process.env.SUBMISSION_USERNAME || '',
  submissionPassword: process.env.SUBMISSION_PASSWORD || '',
  submissionAllowInsecureAuth: String(process.env.SUBMISSION_ALLOW_INSECURE_AUTH || '').toLowerCase() === 'true',
  submissionTlsCert: process.env.SUBMISSION_TLS_CERT || '',
  submissionTlsKey: process.env.SUBMISSION_TLS_KEY || '',
  submissionMaxMessageBytes: Number(process.env.SUBMISSION_MAX_MESSAGE_BYTES || 50 * 1024 * 1024),
  imapEnabled: String(process.env.IMAP_ENABLED || 'true').toLowerCase() !== 'false',
  imapListeners: parseMailboxAccessListeners(process.env.IMAP_PORTS, '143:imap,993:imaps'),
  pop3Enabled: String(process.env.POP3_ENABLED || 'true').toLowerCase() !== 'false',
  pop3Listeners: parseMailboxAccessListeners(process.env.POP3_PORTS, '110:pop3,995:pop3s'),
  mailboxAccessAllowInsecureAuth:
    String(process.env.MAIL_ACCESS_ALLOW_INSECURE_AUTH || process.env.SUBMISSION_ALLOW_INSECURE_AUTH || '').toLowerCase() === 'true',
  inboundEnabled: String(process.env.INBOUND_ENABLED || 'true').toLowerCase() !== 'false',
  sessionSecret: process.env.SESSION_SECRET || fallbackSecret,
  trackingSecret: process.env.TRACKING_SECRET || process.env.SESSION_SECRET || fallbackSecret,
  trustProxy: String(process.env.TRUST_PROXY || '').toLowerCase() === 'true',
  trackingRetentionDays: Math.max(1, Number(process.env.TRACKING_RETENTION_DAYS || 180))
};

const defaultSettings = {
  appBaseUrl: process.env.APP_BASE_URL || 'http://127.0.0.1:3000',
  mailHostname: process.env.MAIL_HOSTNAME || 'mailhub.local',
  sendingIp: process.env.SENDING_IP || '',
  defaultSpfMechanisms: process.env.DEFAULT_SPF_MECHANISMS || 'include:spf.mailjet.com',
  dmarcPolicy: process.env.DMARC_POLICY || 'none',
  dmarcRua: process.env.DMARC_RUA || '',
  sendRequiresVerified: String(process.env.SEND_REQUIRES_VERIFIED || '').toLowerCase() === 'true' ? 'true' : 'false',
  engagementTrackingEnabled:
    String(process.env.ENGAGEMENT_TRACKING_ENABLED || '').toLowerCase() === 'true' ? 'true' : 'false',
  listUnsubscribeMailto: process.env.LIST_UNSUBSCRIBE_MAILTO || '',
  listUnsubscribeUrl: process.env.LIST_UNSUBSCRIBE_URL || '',
  listUnsubscribePostEnabled:
    String(process.env.LIST_UNSUBSCRIBE_POST_ENABLED || '').toLowerCase() === 'true' ? 'true' : 'false',
  feedbackIdEnabled: String(process.env.FEEDBACK_ID_ENABLED || 'true').toLowerCase() === 'false' ? 'false' : 'true',
  reportAbuseTo: process.env.REPORT_ABUSE_TO || '',
  csaComplaintsTo: process.env.CSA_COMPLAINTS_TO || '',
  bounceAddress: process.env.BOUNCE_ADDRESS || '',
  bounceEnvelopeEnabled:
    String(process.env.BOUNCE_ENVELOPE_ENABLED || '').toLowerCase() === 'true' ? 'true' : 'false'
};

const emailVerificationPurpose = 'email_verification';
const passwordResetPurpose = 'password_reset';

initDatabase(envConfig.dataDir, envConfig.sessionSecret);
const admin = seedAdminUser({
  username: envConfig.adminUser,
  email: envConfig.adminEmail,
  password: envConfig.adminPassword
});
claimLegacyData(admin.id);
seedSmtpCredential(admin.id, envConfig.submissionUsername, envConfig.submissionPassword);

startPostfixDeliveryTracker({
  enabled: envConfig.deliveryTrackingEnabled,
  logFile: envConfig.postfixLogFile,
  pollIntervalMs: envConfig.postfixLogPollIntervalMs
});

startDnsAutoChecker({
  enabled: envConfig.dnsAutoCheckEnabled,
  intervalMs: envConfig.dnsAutoCheckIntervalMs,
  limit: envConfig.dnsAutoCheckLimit
});

startWebhookWorker({
  enabled: envConfig.webhookWorkerEnabled,
  intervalMs: envConfig.webhookWorkerIntervalMs,
  batchSize: envConfig.webhookWorkerBatchSize
});

startTrackingRetentionWorker({
  days: envConfig.trackingRetentionDays
});

const server = http.createServer(async (req, res) => {
  try {
    setSecurityHeaders(res);
    if (req.method === 'OPTIONS') return handleOptions(res);
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    if (url.pathname === '/healthz') return sendJson(res, 200, { ok: true });
    if (url.pathname.startsWith('/t/') && await handleTrackingRequest(req, res, url)) return;
    if (req.method === 'POST' && (url.pathname === '/api/register' || url.pathname === '/register')) return await handleRegister(req, res);
    if (req.method === 'POST' && (url.pathname === '/api/login' || url.pathname === '/login')) return await handleLogin(req, res);
    if (req.method === 'POST' && url.pathname === '/api/logout') return handleLogout(res);
    if (url.pathname === '/api/auth/verify-email') return await handleVerifyEmail(req, res, url);
    if (req.method === 'POST' && url.pathname === '/api/auth/resend-verification') return await handleResendVerification(req, res);
    if (req.method === 'POST' && url.pathname === '/api/auth/forgot-password') return await handleForgotPassword(req, res);
    if (req.method === 'POST' && url.pathname === '/api/auth/reset-password') return await handleResetPassword(req, res);

    const user = getRequestUser(req, url.pathname);

    if (url.pathname === '/' || url.pathname === '/index.html' || url.pathname === '/landing.html') {
      if (user && (url.pathname === '/' || url.pathname === '/index.html')) {
        return sendStaticFile(res, path.join(__dirname, '..', 'public', 'index.html'), { noStore: true });
      }
      if (!user && (url.pathname === '/' || url.pathname === '/landing.html')) {
        return sendStaticFile(res, path.join(__dirname, '..', 'public', 'landing.html'), { noStore: true });
      }
      if (user && url.pathname === '/landing.html') {
        return redirect(res, '/');
      }
    }

    if (isLoginAsset(url.pathname)) {
      if ((url.pathname === '/login' || url.pathname === '/register') && user) return redirect(res, '/');
      return await serveStatic(req, res, url);
    }

    if (!user) {
      if (url.pathname.startsWith('/api/')) return sendJson(res, 401, { error: 'Authentication required.' });
      return redirect(res, '/login');
    }

    if (url.pathname.startsWith('/api/')) return await handleApi(req, res, url, user);
    return await serveStatic(req, res, url);
  } catch (error) {
    console.error(error);
    return sendJson(res, 500, { error: error.message || 'Internal server error.' });
  }
});

server.listen(envConfig.port, '0.0.0.0', () => {
  console.log(`MailHub listening on 0.0.0.0:${envConfig.port}`);
});

startSubmissionServer({
  enabled: envConfig.submissionEnabled,
  listeners: envConfig.submissionListeners,
  hostname: envConfig.submissionHost,
  allowInsecureAuth: envConfig.submissionAllowInsecureAuth,
  inboundEnabled: envConfig.inboundEnabled,
  maxMessageBytes: envConfig.submissionMaxMessageBytes,
  tlsCertPath: envConfig.submissionTlsCert,
  tlsKeyPath: envConfig.submissionTlsKey,
  relayHost: envConfig.smtpHost,
  relayPort: envConfig.smtpPort,
  relaySecure: envConfig.smtpSecure,
  relayUsername: envConfig.smtpUser,
  relayPassword: envConfig.smtpPassword,
  relayHelo: envConfig.smtpHelo,
  getTrackingSettings() {
    const settings = runtimeSettings();
    return {
      enabled: settings.engagementTrackingEnabled,
      appBaseUrl: settings.appBaseUrl,
      secret: envConfig.trackingSecret
    };
  },
  getDeliverabilitySettings() {
    return {
      ...runtimeSettings(),
      secret: envConfig.trackingSecret
    };
  }
});

startMailboxAccessServers({
  hostname: envConfig.submissionHost,
  imapEnabled: envConfig.imapEnabled,
  imapListeners: envConfig.imapListeners,
  pop3Enabled: envConfig.pop3Enabled,
  pop3Listeners: envConfig.pop3Listeners,
  allowInsecureAuth: envConfig.mailboxAccessAllowInsecureAuth,
  tlsCertPath: envConfig.submissionTlsCert,
  tlsKeyPath: envConfig.submissionTlsKey
});

async function handleApi(req, res, url, user) {
  const method = req.method || 'GET';
  const pathname = url.pathname;

  if (method === 'GET' && pathname === '/api/me') {
    return sendJson(res, 200, { user });
  }
  if (method === 'GET' && pathname === '/api/config') {
    return sendJson(res, 200, publicConfig(user));
  }
  if (method === 'GET' && pathname === '/api/domains') {
    return sendJson(res, 200, { domains: listDomains(user.id) });
  }
  if (method === 'POST' && pathname === '/api/domains') {
    const body = await readJson(req);
    const settings = runtimeSettings();
    const domain = normalizeDomain(body.domain);
    if (!domain) return sendJson(res, 400, { error: '域名格式不正确。' });
    const selector = normalizeSelector(body.selector || defaultSelector());
    if (!selector) return sendJson(res, 400, { error: 'DKIM selector 格式不正确。' });
    const dnsCredentialId = Number(body.dnsCredentialId || 0) || null;
    if (dnsCredentialId && !getDnsCredential(dnsCredentialId, user.id)) {
      return sendJson(res, 400, { error: 'DNS 凭据不存在。' });
    }
    const smtpRelayId = Number(body.smtpRelayId || 0) || null;
    if (smtpRelayId && !getSmtpRelay(smtpRelayId, user.id)) {
      return sendJson(res, 400, { error: 'SMTP 出口不存在。' });
    }
    const keys = createDkimKeyPair();
    try {
      const row = createDomain(user.id, {
        domain,
        selector,
        dnsCredentialId,
        smtpRelayId,
        verificationToken: crypto.randomBytes(18).toString('hex'),
        dkimPublic: keys.publicKey,
        dkimPrivate: keys.privateKey,
        senderHost: normalizeHostname(body.senderHost || settings.mailHostname),
        sendingIp: String(body.sendingIp || settings.sendingIp).trim(),
        spfExtra: String(body.spfExtra ?? settings.defaultSpfMechanisms).trim(),
        dmarcPolicy: normalizeDmarcPolicy(body.dmarcPolicy || settings.dmarcPolicy),
        dmarcRua: String(body.dmarcRua ?? settings.dmarcRua).trim()
      });
      return sendJson(res, 201, { domain: row });
    } catch (error) {
      if (isUniqueError(error)) return sendJson(res, 409, { error: '该域名已被添加。' });
      throw error;
    }
  }
  if (method === 'GET' && pathname === '/api/events') {
    return sendJson(res, 200, { events: listSendEvents(user.id) });
  }
  if (method === 'GET' && pathname === '/api/inbound-mailboxes') {
    return sendJson(res, 200, { mailboxes: listInboundMailboxes(user.id) });
  }
  if (method === 'POST' && pathname === '/api/inbound-mailboxes') {
    const body = await readJson(req);
    const password = String(body.password || '');
    if (password.length < 8) return sendJson(res, 400, { error: '邮箱密码至少需要 8 位。' });
    try {
      const mailbox = createInboundMailbox(user.id, inboundMailboxPatch({
        ...body,
        password
      }));
      return sendJson(res, 201, {
        mailbox,
        clientConfig: mailboxClientConfig(mailbox, { password })
      });
    } catch (error) {
      if (isUniqueError(error)) return sendJson(res, 409, { error: '该收信邮箱已存在。' });
      return sendJson(res, 400, { error: error.message || '收信邮箱创建失败。' });
    }
  }
  const inboundMailboxMatch = pathname.match(/^\/api\/inbound-mailboxes\/(\d+)$/);
  if (inboundMailboxMatch && (method === 'PATCH' || method === 'PUT')) {
    const body = await readJson(req);
    try {
      const mailbox = updateInboundMailbox(user.id, Number(inboundMailboxMatch[1]), inboundMailboxPatch(body));
      if (!mailbox) return sendJson(res, 404, { error: '收信邮箱不存在。' });
      return sendJson(res, 200, {
        mailbox,
        clientConfig: body.password ? mailboxClientConfig(mailbox, { password: String(body.password || '') }) : undefined
      });
    } catch (error) {
      return sendJson(res, 400, { error: error.message || '收信邮箱更新失败。' });
    }
  }
  if (method === 'GET' && pathname === '/api/inbound-messages') {
    return sendJson(res, 200, {
      messages: listInboundMessages(user.id, {
        mailboxId: Number(url.searchParams.get('mailboxId') || 0) || null
      })
    });
  }
  const inboundMessageMatch = pathname.match(/^\/api\/inbound-messages\/(\d+)$/);
  if (inboundMessageMatch) {
    const id = Number(inboundMessageMatch[1]);
    if (method === 'GET') {
      const message = getInboundMessage(user.id, id);
      return sendJson(res, message ? 200 : 404, { message });
    }
    if (method === 'PATCH') {
      const body = await readJson(req);
      const message = markInboundMessageRead(user.id, id, body.read !== false);
      return sendJson(res, message ? 200 : 404, { message });
    }
  }
  const sendEventMatch = pathname.match(/^\/api\/events\/(\d+)$/);
  if (sendEventMatch && method === 'GET') {
    const event = getSendEvent(user.id, Number(sendEventMatch[1]), { trackingSecret: envConfig.trackingSecret });
    return sendJson(res, event ? 200 : 404, { event });
  }
  if (method === 'GET' && pathname === '/api/analytics') {
    return sendJson(res, 200, {
      analytics: getSendAnalytics(user.id, {
        days: Number(url.searchParams.get('days') || 7),
        trackingSecret: envConfig.trackingSecret
      })
    });
  }
  if (method === 'GET' && pathname === '/api/smtp-credential') {
    return sendJson(res, 200, { credential: getSmtpCredential(user.id, { includePassword: true }) });
  }
  if ((method === 'POST' || method === 'PUT' || method === 'PATCH') && pathname === '/api/smtp-credential') {
    const body = await readJson(req);
    try {
      const current = getSmtpCredential(user.id);
      saveSmtpCredential(user.id, {
        id: current?.id || null,
        username: String(body.username || '').trim(),
        password: String(body.password || '')
      });
    } catch (error) {
      if (isUniqueError(error)) return sendJson(res, 409, { error: 'SMTP 用户名已被占用。' });
      throw error;
    }
    return sendJson(res, 200, { credential: getSmtpCredential(user.id, { includePassword: true }) });
  }
  if (method === 'GET' && pathname === '/api/smtp-credentials') {
    return sendJson(res, 200, { credentials: listSmtpCredentials(user.id, { includePassword: true }) });
  }
  if (method === 'POST' && pathname === '/api/smtp-credentials') {
    const body = await readJson(req);
    try {
      const credential = saveSmtpCredential(user.id, {
        username: String(body.username || '').trim(),
        password: String(body.password || '')
      });
      return sendJson(res, 201, { credential: getSmtpCredential(credential.id, user.id, { includePassword: true }) });
    } catch (error) {
      if (isUniqueError(error)) return sendJson(res, 409, { error: 'SMTP 用户名已被占用。' });
      throw error;
    }
  }
  const smtpCredentialMatch = pathname.match(/^\/api\/smtp-credentials\/(\d+)$/);
  if (smtpCredentialMatch) {
    const id = Number(smtpCredentialMatch[1]);
    if (method === 'GET') {
      const credential = getSmtpCredential(id, user.id, { includePassword: true });
      return sendJson(res, credential ? 200 : 404, { credential });
    }
    if (method === 'PATCH' || method === 'PUT') {
      const body = await readJson(req);
      try {
        const credential = saveSmtpCredential(user.id, {
          id,
          username: String(body.username || '').trim(),
          password: String(body.password || '')
        });
        return sendJson(res, credential ? 200 : 404, {
          credential: credential ? getSmtpCredential(credential.id, user.id, { includePassword: true }) : null
        });
      } catch (error) {
        if (isUniqueError(error)) return sendJson(res, 409, { error: 'SMTP 用户名已被占用。' });
        throw error;
      }
    }
    if (method === 'DELETE') {
      const deleted = deleteSmtpCredential(id, user.id);
      return sendJson(res, deleted ? 200 : 404, { deleted });
    }
  }
  if (method === 'GET' && pathname === '/api/smtp-relays') {
    return sendJson(res, 200, { relays: listSmtpRelays(user.id) });
  }
  if (method === 'POST' && pathname === '/api/smtp-relays') {
    const body = await readJson(req);
    const relay = saveSmtpRelay(user.id, smtpRelayPatch(body));
    return sendJson(res, 201, { relay });
  }
  const smtpRelayMatch = pathname.match(/^\/api\/smtp-relays\/(\d+)$/);
  if (smtpRelayMatch) {
    const id = Number(smtpRelayMatch[1]);
    if (method === 'GET') {
      const relay = getSmtpRelay(id, user.id, { includePassword: true });
      return sendJson(res, relay ? 200 : 404, { relay });
    }
    if (method === 'PATCH' || method === 'PUT') {
      const body = await readJson(req);
      const relay = saveSmtpRelay(user.id, { ...smtpRelayPatch(body), id });
      return sendJson(res, relay ? 200 : 404, { relay });
    }
    if (method === 'DELETE') {
      const deleted = deleteSmtpRelay(id, user.id);
      return sendJson(res, deleted ? 200 : 404, { deleted });
    }
  }
  if (method === 'POST' && pathname === '/api/send') {
    if (!requireApiTokenScope(req, res, 'send')) return;
    const body = await readJson(req);
    const smtpRelayId = Number(body.smtpRelayId || 0) || null;
    if (smtpRelayId && !getSmtpRelay(smtpRelayId, user.id)) {
      return sendJson(res, 400, { error: 'SMTP 出口不存在。' });
    }
    const result = await sendMailFromBody(body, user);
    return sendJson(res, 202, result);
  }

  if (method === 'GET' && pathname === '/api/mailboxes') {
    if (!requireApiTokenScope(req, res, 'mailboxes:read')) return;
    return sendJson(res, 200, { mailboxes: listInboundMailboxes(user.id) });
  }
  if (method === 'POST' && pathname === '/api/mailboxes') {
    if (!requireApiTokenScope(req, res, 'mailboxes:write')) return;
    const body = await readJson(req);
    try {
      const request = mailboxApiRequest(body);
      const mailbox = createInboundMailbox(user.id, request.mailbox);
      return sendJson(res, 201, {
        mailbox,
        mode: request.mode,
        password: request.password,
        clientConfig: mailboxClientConfig(mailbox, { password: request.password })
      });
    } catch (error) {
      if (isUniqueError(error)) return sendJson(res, 409, { error: '该收信邮箱已存在。' });
      return sendJson(res, 400, { error: error.message || '邮箱创建失败。' });
    }
  }

  if (method === 'GET' && pathname === '/api/api-tokens') {
    return sendJson(res, 200, { tokens: listApiTokens(user.id) });
  }
  if (method === 'POST' && pathname === '/api/api-tokens') {
    const body = await readJson(req);
    try {
      return sendJson(res, 201, {
        token: createApiToken(user.id, body.name, {
          scopes: body.scopes,
          expiresAt: body.expiresAt
        })
      });
    } catch (error) {
      return sendJson(res, 400, { error: error.message || 'API Token 创建失败。' });
    }
  }
  const tokenMatch = pathname.match(/^\/api\/api-tokens\/(\d+)$/);
  if (tokenMatch && (method === 'PATCH' || method === 'PUT')) {
    const body = await readJson(req);
    try {
      const token = updateApiToken(Number(tokenMatch[1]), user.id, body);
      return sendJson(res, token ? 200 : 404, token ? { token } : { error: 'API Token 不存在。' });
    } catch (error) {
      return sendJson(res, 400, { error: error.message || 'API Token 更新失败。' });
    }
  }
  if (tokenMatch && method === 'DELETE') {
    const revoked = revokeApiToken(Number(tokenMatch[1]), user.id);
    return sendJson(res, revoked ? 200 : 404, {
      revoked,
      deleted: revoked,
      token: revoked ? getApiToken(Number(tokenMatch[1]), user.id) : null
    });
  }

  if (method === 'GET' && pathname === '/api/dns-credentials') {
    return sendJson(res, 200, { credentials: listDnsCredentials(user.id) });
  }
  if (method === 'POST' && pathname === '/api/dns-credentials') {
    const body = await readJson(req);
    const credential = saveDnsCredential(user.id, body);
    return sendJson(res, 201, { credential });
  }
  const dnsMatch = pathname.match(/^\/api\/dns-credentials\/(\d+)(?:\/([a-z-]+))?$/);
  if (dnsMatch) {
    const id = Number(dnsMatch[1]);
    const action = dnsMatch[2] || '';
    if ((method === 'PUT' || method === 'PATCH') && !action) {
      const body = await readJson(req);
      const credential = saveDnsCredential(user.id, { ...body, id });
      return sendJson(res, credential ? 200 : 404, { credential });
    }
    if (method === 'DELETE' && !action) {
      const deleted = deleteDnsCredential(id, user.id);
      return sendJson(res, deleted ? 200 : 404, { deleted });
    }
    if (method === 'POST' && action === 'test') {
      const credential = getDnsCredential(id, user.id, { includeCredentials: true });
      if (!credential) return sendJson(res, 404, { error: 'DNS 凭据不存在。' });
      const result = await testDnsCredential(credential);
      return sendJson(res, result.ok ? 200 : 400, result);
    }
  }

  if (method === 'GET' && pathname === '/api/webhooks') {
    let domainId;
    let mailboxId;
    if (url.searchParams.has('domainId')) {
      const raw = url.searchParams.get('domainId');
      if (raw === '' || raw === 'null') {
        domainId = null;
      } else {
        domainId = Number(raw);
        if (!Number.isInteger(domainId) || domainId <= 0) {
          return sendJson(res, 400, { error: 'domainId 无效。' });
        }
      }
    }
    if (url.searchParams.has('mailboxId')) {
      const raw = url.searchParams.get('mailboxId');
      mailboxId = Number(raw);
      if (!Number.isInteger(mailboxId) || mailboxId <= 0) {
        return sendJson(res, 400, { error: 'mailboxId 无效。' });
      }
    }
    if (domainId !== undefined && mailboxId !== undefined) {
      return sendJson(res, 400, { error: 'Webhook 不能同时按域名和收信邮箱筛选。' });
    }
    try {
      return sendJson(res, 200, { webhooks: listWebhooks(user.id, { domainId, mailboxId }) });
    } catch (error) {
      return sendJson(res, 400, { error: error.message || 'Webhook 查询失败。' });
    }
  }
  if (method === 'POST' && pathname === '/api/webhooks') {
    const body = await readJson(req);
    try {
      await assertSafeWebhookUrl(String(body.url || '').trim());
      const webhook = createWebhook(user.id, {
        name: body.name,
        url: body.url,
        events: body.events,
        domainId: body.domainId === undefined ? null : body.domainId,
        mailboxId: body.mailboxId === undefined ? null : body.mailboxId,
        enabled: body.enabled
      });
      return sendJson(res, 201, { webhook });
    } catch (error) {
      return sendJson(res, 400, { error: error.message || 'Webhook 创建失败。' });
    }
  }
  const webhookMatch = pathname.match(/^\/api\/webhooks\/(\d+)(?:\/(rotate-secret|test))?$/);
  if (webhookMatch) {
    const id = Number(webhookMatch[1]);
    const action = webhookMatch[2] || '';
    if (method === 'PATCH' && !action) {
      const body = await readJson(req);
      try {
        if (body.url !== undefined) {
          await assertSafeWebhookUrl(String(body.url || '').trim());
        }
        const patch = {};
        if (body.name !== undefined) patch.name = body.name;
        if (body.url !== undefined) patch.url = body.url;
        if (body.events !== undefined) patch.events = body.events;
        if (body.domainId !== undefined) patch.domainId = body.domainId;
        if (body.mailboxId !== undefined) patch.mailboxId = body.mailboxId;
        if (body.enabled !== undefined) patch.enabled = body.enabled;
        const webhook = updateWebhook(user.id, id, patch);
        if (!webhook) return sendJson(res, 404, { error: 'Webhook 不存在。' });
        return sendJson(res, 200, { webhook });
      } catch (error) {
        return sendJson(res, 400, { error: error.message || 'Webhook 更新失败。' });
      }
    }
    if (method === 'DELETE' && !action) {
      const deleted = deleteWebhook(user.id, id);
      return sendJson(res, deleted ? 200 : 404, { deleted });
    }
    if (method === 'POST' && action === 'rotate-secret') {
      const webhook = rotateWebhookSecret(user.id, id);
      if (!webhook) return sendJson(res, 404, { error: 'Webhook 不存在。' });
      return sendJson(res, 200, { webhook });
    }
    if (method === 'POST' && action === 'test') {
      try {
        const delivery = enqueueWebhookTestDelivery(user.id, id);
        if (!delivery) return sendJson(res, 404, { error: 'Webhook 不存在。' });
        return sendJson(res, 202, { delivery });
      } catch (error) {
        return sendJson(res, 400, { error: error.message || 'Webhook 测试失败。' });
      }
    }
  }

  if (method === 'GET' && pathname === '/api/webhook-deliveries') {
    const filters = {};
    if (url.searchParams.has('status')) filters.status = url.searchParams.get('status');
    if (url.searchParams.has('webhookId')) filters.webhookId = Number(url.searchParams.get('webhookId'));
    if (url.searchParams.has('eventType')) filters.eventType = url.searchParams.get('eventType');
    if (url.searchParams.has('limit')) filters.limit = url.searchParams.get('limit');
    return sendJson(res, 200, { deliveries: listWebhookDeliveries(user.id, filters) });
  }
  const webhookDeliveryReplayMatch = pathname.match(/^\/api\/webhook-deliveries\/(\d+)\/replay$/);
  if (webhookDeliveryReplayMatch && method === 'POST') {
    try {
      const delivery = replayWebhookDelivery(user.id, Number(webhookDeliveryReplayMatch[1]));
      if (!delivery) return sendJson(res, 404, { error: 'Webhook 投递记录不存在。' });
      return sendJson(res, 200, { delivery });
    } catch (error) {
      return sendJson(res, 400, { error: error.message || 'Webhook 重放失败。' });
    }
  }

  if (pathname.startsWith('/api/admin/')) {
    return await handleAdminApi(req, res, url, user);
  }

  const domainMatch = pathname.match(/^\/api\/domains\/(\d+)(?:\/([a-z-]+))?$/);
  if (domainMatch) {
    const id = Number(domainMatch[1]);
    const action = domainMatch[2] || '';
    if (method === 'GET' && !action) {
      const domain = getDomain(id, { userId: user.id });
      if (!domain) return sendJson(res, 404, { error: '域名不存在。' });
      return sendJson(res, 200, { domain });
    }
    if (method === 'PATCH' && !action) {
      const body = await readJson(req);
      const dnsCredentialId = body.dnsCredentialId !== undefined ? Number(body.dnsCredentialId || 0) || null : undefined;
      if (dnsCredentialId && !getDnsCredential(dnsCredentialId, user.id)) {
        return sendJson(res, 400, { error: 'DNS 凭据不存在。' });
      }
      const smtpRelayId = body.smtpRelayId !== undefined ? Number(body.smtpRelayId || 0) || null : undefined;
      if (smtpRelayId && !getSmtpRelay(smtpRelayId, user.id)) {
        return sendJson(res, 400, { error: 'SMTP 出口不存在。' });
      }
      const catchAllAddress = body.catchAllAddress !== undefined ? normalizeCatchAllAddress(body.catchAllAddress) : undefined;
      if (body.catchAllAddress && !catchAllAddress) {
        return sendJson(res, 400, { error: '收取未知邮件的邮箱格式不正确。' });
      }
      const row = updateDomain(id, user.id, {
        selector: body.selector ? normalizeSelector(body.selector) : undefined,
        dnsCredentialId,
        smtpRelayId,
        senderHost: body.senderHost ? normalizeHostname(body.senderHost) : undefined,
        sendingIp: body.sendingIp !== undefined ? String(body.sendingIp).trim() : undefined,
        spfExtra: body.spfExtra !== undefined ? String(body.spfExtra).trim() : undefined,
        dmarcPolicy: body.dmarcPolicy ? normalizeDmarcPolicy(body.dmarcPolicy) : undefined,
        dmarcRua: body.dmarcRua !== undefined ? String(body.dmarcRua).trim() : undefined,
        catchAllAddress
      });
      if (!row) return sendJson(res, 404, { error: '域名不存在。' });
      return sendJson(res, 200, { domain: row });
    }
    if (method === 'DELETE' && !action) {
      const deleted = deleteDomain(id, user.id);
      return sendJson(res, deleted ? 200 : 404, { deleted });
    }
    if (method === 'POST' && action === 'check') {
      const row = getDomain(id, { userId: user.id });
      if (!row) return sendJson(res, 404, { error: '域名不存在。' });
      const guide = await buildDnsGuide(row);
      saveDomainStatus(id, user.id, guide);
      return sendJson(res, 200, { guide, domain: getDomain(id, { userId: user.id }) });
    }
    if (method === 'POST' && action === 'apply-dns') {
      const row = getDomain(id, { userId: user.id, includePrivate: true });
      if (!row) return sendJson(res, 404, { error: '域名不存在。' });
      const credentialId = Number(row.dnsCredentialId || 0);
      const credential = credentialId ? getDnsCredential(credentialId, user.id, { includeCredentials: true }) : null;
      if (!credential) return sendJson(res, 400, { error: '请先为该域名绑定 DNS API 凭据。' });
      const guide = await buildDnsGuide(row);
      const applyResult = await applyDnsSetup(row, credential, guide);
      const checkedGuide = await buildDnsGuideAfterApply(row, applyResult);
      checkedGuide.apply = applyResult;
      saveDomainStatus(id, user.id, checkedGuide);
      return sendJson(res, applyResult.ok ? 200 : 207, {
        apply: applyResult,
        guide: checkedGuide,
        domain: getDomain(id, { userId: user.id })
      });
    }
    if (method === 'POST' && action === 'rotate-dkim') {
      const row = getDomain(id, { userId: user.id });
      if (!row) return sendJson(res, 404, { error: '域名不存在。' });
      const body = await readJson(req).catch(() => ({}));
      const selector = normalizeSelector(body.selector || defaultSelector());
      const next = updateDkim(id, user.id, createDkimKeyPair(), selector);
      return sendJson(res, 200, { domain: next });
    }
    if (method === 'POST' && action === 'test-send') {
      const row = getDomain(id, { userId: user.id });
      if (!row) return sendJson(res, 404, { error: '域名不存在。' });
      const body = await readJson(req);
      const smtpRelayId = Number(body.smtpRelayId || 0) || null;
      if (smtpRelayId && !getSmtpRelay(smtpRelayId, user.id)) {
        return sendJson(res, 400, { error: 'SMTP 出口不存在。' });
      }
      const from = body.from || `noreply@${row.domain}`;
      const result = await sendMailFromBody({
        from,
        to: body.to,
        subject: body.subject || `MailHub test for ${row.domain}`,
        text: body.text || `This is a MailHub test message from ${row.domain}.`,
        html: body.html,
        tracking: body.tracking,
        smtpRelayId: body.smtpRelayId
      }, user);
      return sendJson(res, 202, result);
    }
  }

  return sendJson(res, 404, { error: 'Not found.' });
}

async function handleAdminApi(req, res, url, user) {
  const method = req.method || 'GET';
  const pathname = url.pathname;
  if (!pathname.startsWith('/api/admin/')) return null;
  if (user.role !== 'admin') return sendJson(res, 403, { error: '需要管理员权限。' });
  if (method === 'GET' && pathname === '/api/admin/settings') {
    return sendJson(res, 200, { settings: await adminRuntimeSettings() });
  }
  if (method === 'GET' && pathname === '/api/admin/system-email') {
    return sendJson(res, 200, { settings: getSystemEmailSettings() });
  }
  if (method === 'GET' && pathname === '/api/admin/audit-logs') {
    return sendJson(res, 200, { logs: listAuditLogs(adminAuditFilters(url.searchParams)) });
  }
  if (method === 'GET' && pathname === '/api/admin/resources') {
    return sendJson(res, 200, { inventory: getAdminResourceInventory() });
  }
  const transferDomainMatch = pathname.match(/^\/api\/admin\/resources\/domains\/(\d+)\/transfer$/);
  if (transferDomainMatch && method === 'POST') {
    const body = await readJson(req);
    try {
      const domain = transferDomain({
        actorUserId: user.id,
        domainId: Number(transferDomainMatch[1]),
        targetUserId: body.targetUserId,
        dnsCredentialMode: body.dnsCredentialMode
      });
      return sendJson(res, 200, { domain });
    } catch (error) {
      return sendAdminTransferError(res, error);
    }
  }
  const transferDnsCredentialMatch = pathname.match(/^\/api\/admin\/resources\/dns-credentials\/(\d+)\/transfer$/);
  if (transferDnsCredentialMatch && method === 'POST') {
    const body = await readJson(req);
    try {
      const credential = transferDnsCredential({
        actorUserId: user.id,
        credentialId: Number(transferDnsCredentialMatch[1]),
        targetUserId: body.targetUserId
      });
      return sendJson(res, 200, { credential });
    } catch (error) {
      return sendAdminTransferError(res, error);
    }
  }
  if (method === 'POST' && pathname === '/api/admin/resources/api-tokens/transfer') {
    const body = await readJson(req);
    try {
      const tokens = transferApiTokens({
        actorUserId: user.id,
        tokenIds: body.tokenIds,
        targetUserId: body.targetUserId
      });
      return sendJson(res, 200, { tokens });
    } catch (error) {
      return sendAdminTransferError(res, error);
    }
  }
  if (method === 'POST' && pathname === '/api/admin/migrations/user-merge/preview') {
    const body = await readJson(req);
    try {
      const preview = previewUserMerge({
        sourceUserId: body.sourceUserId,
        targetUserId: body.targetUserId
      });
      return sendJson(res, 200, { preview });
    } catch (error) {
      return sendAdminMigrationError(res, error);
    }
  }
  if (method === 'POST' && pathname === '/api/admin/migrations/user-merge/execute') {
    const body = await readJson(req);
    try {
      const result = executeUserMerge({
        actorUserId: user.id,
        sourceUserId: body.sourceUserId,
        targetUserId: body.targetUserId,
        options: body.options,
        confirmation: body.confirmation
      });
      return sendJson(res, 200, { result });
    } catch (error) {
      return sendAdminMigrationError(res, error);
    }
  }
  if ((method === 'PATCH' || method === 'PUT') && pathname === '/api/admin/system-email') {
    const body = await readJson(req);
    const settings = saveSystemEmailSettings({
      host: body.host,
      port: body.port,
      secure: body.secure,
      username: body.username,
      password: body.password,
      helo: body.helo,
      fromEmail: body.fromEmail,
      fromName: body.fromName,
      testRecipient: body.testRecipient
    });
    logAudit({
      actorUserId: user.id,
      action: 'admin.update_system_email',
      targetType: 'system_email',
      targetId: 'default',
      summary: settings
    });
    return sendJson(res, 200, { settings });
  }
  if (method === 'POST' && pathname === '/api/admin/system-email/test') {
    const body = await readJson(req).catch(() => ({}));
    const settings = systemMailSettingsForSend();
    const to = extractAddress(body.to || settings.testRecipient);
    if (!to) return sendJson(res, 400, { error: '测试收件人地址格式不正确。' });
    const result = await sendSystemEmail(settings, {
      to,
      subject: 'MailHub 系统邮件测试',
      text: '这是一封 MailHub 系统邮件测试。'
    });
    logAudit({
      actorUserId: user.id,
      action: 'admin.test_system_email',
      targetType: 'system_email',
      targetId: 'default',
      summary: {
        to,
        ok: result.ok,
        message: result.message,
        queueId: result.queueId
      }
    });
    return sendJson(res, result.ok ? 202 : 502, { result });
  }
  if ((method === 'PATCH' || method === 'PUT') && pathname === '/api/admin/settings') {
    const body = await readJson(req);
    saveSettings(settingsPatchFromBody(body));
    return sendJson(res, 200, { settings: await adminRuntimeSettings() });
  }
  if (method === 'GET' && pathname === '/api/admin/users') {
    return sendJson(res, 200, { users: listUsersWithResourceCounts() });
  }
  const approveMatch = pathname.match(/^\/api\/admin\/users\/(\d+)\/approve$/);
  if (approveMatch && method === 'POST') {
    const current = getUser(Number(approveMatch[1]));
    if (!current) return sendJson(res, 404, { error: '用户不存在。' });
    if (current.status === 'pending_email') return sendJson(res, 400, { error: '用户尚未验证邮箱。' });
    if (current.status !== 'pending_review') return sendJson(res, 400, { error: '只能审批等待审核的用户。' });
    const target = approveUser(current.id);
    if (!target) return sendJson(res, 404, { error: '用户不存在。' });
    logAudit({
      actorUserId: user.id,
      action: 'admin.approve_user',
      targetType: 'user',
      targetId: String(target.id),
      targetUserId: target.id,
      summary: {
        username: target.username,
        status: target.status
      }
    });
    return sendJson(res, 200, { user: target });
  }
  const resendVerificationMatch = pathname.match(/^\/api\/admin\/users\/(\d+)\/resend-verification$/);
  if (resendVerificationMatch && method === 'POST') {
    const target = getUser(Number(resendVerificationMatch[1]));
    if (!target) return sendJson(res, 404, { error: '用户不存在。' });
    if (target.status !== 'pending_email') return sendJson(res, 400, { error: '用户不需要重新发送验证邮件。' });
    const result = await createAndSendVerificationEmail(target);
    logAudit({
      actorUserId: user.id,
      action: 'admin.resend_verification',
      targetType: 'user',
      targetId: String(target.id),
      targetUserId: target.id,
      summary: {
        username: target.username,
        email: target.email,
        verificationEmailSent: result.ok,
        message: result.message,
        queueId: result.queueId
      }
    });
    return sendJson(res, 202, verificationEmailResponse(result));
  }
  const passwordResetMatch = pathname.match(/^\/api\/admin\/users\/(\d+)\/password-reset$/);
  if (passwordResetMatch && method === 'POST') {
    const target = getUser(Number(passwordResetMatch[1]));
    if (!target) return sendJson(res, 404, { error: '用户不存在。' });
    const result = await createAndSendPasswordResetEmail(target);
    logAudit({
      actorUserId: user.id,
      action: 'admin.password_reset',
      targetType: 'user',
      targetId: String(target.id),
      targetUserId: target.id,
      summary: {
        username: target.username,
        email: target.email,
        ok: result.ok,
        message: result.message,
        queueId: result.queueId
      }
    });
    return sendJson(res, result.ok ? 202 : 502, { result });
  }
  const temporaryPasswordMatch = pathname.match(/^\/api\/admin\/users\/(\d+)\/temporary-password$/);
  if (temporaryPasswordMatch && method === 'POST') {
    const target = getUser(Number(temporaryPasswordMatch[1]));
    if (!target) return sendJson(res, 404, { error: '用户不存在。' });
    const body = await readJson(req);
    let updated;
    try {
      updated = updateUser(target.id, { password: body.password });
    } catch (error) {
      if (error?.message === '密码至少需要 8 位。') return sendJson(res, 400, { error: error.message });
      throw error;
    }
    logAudit({
      actorUserId: user.id,
      action: 'admin.temporary_password',
      targetType: 'user',
      targetId: String(target.id),
      targetUserId: target.id,
      summary: {
        username: target.username,
        email: target.email,
        passwordSet: true
      }
    });
    return sendJson(res, 200, { user: updated });
  }
  const userMatch = pathname.match(/^\/api\/admin\/users\/(\d+)$/);
  if (userMatch && method === 'PATCH') {
    const body = await readJson(req);
    let updated;
    try {
      updated = updateUser(Number(userMatch[1]), {
        role: body.role,
        status: body.status,
        password: body.password
      });
    } catch (error) {
      if (['用户状态不正确。', '密码至少需要 8 位。'].includes(error?.message)) {
        return sendJson(res, 400, { error: error.message });
      }
      throw error;
    }
    return sendJson(res, updated ? 200 : 404, { user: updated });
  }
  return sendJson(res, 404, { error: 'Not found.' });
}

function adminAuditFilters(searchParams) {
  const requested = {
    actorUserId: auditUserIdParam(searchParams.get('actorUserId'), { allowSystem: true }),
    targetUserId: auditUserIdParam(searchParams.get('targetUserId')),
    action: auditTextParam(searchParams.get('action')),
    from: auditDateParam(searchParams.get('from')),
    to: auditDateParam(searchParams.get('to'))
  };
  return Object.fromEntries(
    ['actorUserId', 'targetUserId', 'action', 'from', 'to']
      .filter((key) => requested[key] !== undefined)
      .map((key) => [key, requested[key]])
  );
}

function sendAdminTransferError(res, error) {
  if (['域名不存在。', 'DNS 凭据不存在。', 'API Token 不存在。'].includes(error?.message)) {
    return sendJson(res, 404, { error: error.message });
  }
  if (['目标用户不可用。', 'DNS 凭据归属不一致。'].includes(error?.message)) {
    return sendJson(res, 400, { error: error.message });
  }
  throw error;
}

function sendAdminMigrationError(res, error) {
  if (['源用户不存在。'].includes(error?.message)) return sendJson(res, 404, { error: error.message });
  if ([
    '目标用户不可用。',
    '源用户和目标用户不能相同。',
    '确认文本不匹配。'
  ].includes(error?.message)) {
    return sendJson(res, 400, { error: error.message });
  }
  throw error;
}

function auditUserIdParam(value, { allowSystem = false } = {}) {
  if (value === null) return undefined;
  const text = String(value).trim();
  if (!text) return undefined;
  if (allowSystem && ['system', 'null'].includes(text.toLowerCase())) return null;
  return /^[1-9]\d*$/.test(text) ? Number(text) : undefined;
}

function auditTextParam(value) {
  const text = String(value || '').trim();
  return text || undefined;
}

function auditDateParam(value) {
  const text = String(value || '').trim();
  if (!text) return undefined;
  const dateOnly = text.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (dateOnly) {
    const year = Number(dateOnly[1]);
    const month = Number(dateOnly[2]);
    const day = Number(dateOnly[3]);
    const date = new Date(Date.UTC(year, month - 1, day));
    if (
      date.getUTCFullYear() === year &&
      date.getUTCMonth() === month - 1 &&
      date.getUTCDate() === day
    ) {
      return date.toISOString();
    }
    return undefined;
  }
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(text)) return undefined;
  const date = new Date(text);
  return !Number.isNaN(date.getTime()) && date.toISOString() === text ? text : undefined;
}

async function sendMailFromBody(body, user) {
  const settings = runtimeSettings();
  const from = extractAddress(body.from);
  if (!from) throw new Error('发件人地址格式不正确。');
  const recipients = parseAddressList(body.to);
  if (!recipients.length) throw new Error('收件人地址格式不正确。');
  const fromDomain = domainFromAddress(from);
  const domain = getDomainByName(fromDomain, { userId: user.id, includePrivate: true });
  if (!domain) throw new Error(`发件域名 ${fromDomain} 不属于当前用户或尚未添加。`);
  if (settings.sendRequiresVerified && !domain.status?.verified) {
    throw new Error(`发件域名 ${fromDomain} 尚未完成验证。`);
  }

  const smtpTransport = smtpTransportForSend(body, domain, user);
  const subject = body.subject || '(no subject)';
  const tracking = resolveSendTracking(body, settings, recipients);
  const openToken = tracking.opens ? createTrackingToken() : '';
  const eventId = createSendEvent({
    userId: user.id,
    domainId: domain.id,
    smtpRelayId: smtpTransport.smtpRelayId,
    sender: from,
    recipients,
    subject,
    trackingToken: openToken,
    trackingOpens: tracking.opens,
    trackingClicks: tracking.clicks
  });
  let actualTracking = {
    ...tracking,
    enabled: false,
    opens: false,
    clicks: false
  };
  try {
    let html = body.html || '';
    if (tracking.enabled) {
      const result = instrumentHtml(html, {
        openPixelUrl: tracking.opens ? trackingOpenUrl(settings.appBaseUrl, openToken) : '',
        createClickUrl: tracking.clicks
          ? (target) => createTrackedClickUrl({
              appBaseUrl: settings.appBaseUrl,
              userId: user.id,
              eventId,
              target
            })
          : null
      });
      html = result.html;
      actualTracking = {
        ...tracking,
        enabled: (tracking.opens && result.pixelAdded) || (tracking.clicks && result.linkCount > 0),
        opens: tracking.opens && result.pixelAdded,
        clicks: tracking.clicks && result.linkCount > 0
      };
    }
    const rawMessage = buildMessage({
      from,
      to: recipients,
      subject,
      text: body.text || '',
      html,
      baseUrl: settings.appBaseUrl,
      headers: buildDeliverabilityHeaders({
        from,
        listUnsubscribeMailto: settings.listUnsubscribeMailto,
        listUnsubscribeUrl: settings.listUnsubscribeUrl,
        listUnsubscribePostEnabled: settings.listUnsubscribePostEnabled,
        feedbackId: settings.feedbackIdEnabled
          ? createFeedbackId({
              userId: user.id,
              domainId: domain.id,
              eventId,
              secret: envConfig.trackingSecret
            })
          : '',
        reportAbuseTo: settings.reportAbuseTo,
        csaComplaintsTo: settings.csaComplaintsTo,
        context: {
          eventId,
          userId: user.id,
          domain: fromDomain,
          sender: from,
          recipient: recipients.length === 1 ? recipients[0] : ''
        }
      })
    });
    const signed = signMessageForDomain(rawMessage, domain);
    const smtpResult = await sendViaSmtp({
      host: smtpTransport.host,
      port: smtpTransport.port,
      secure: smtpTransport.secure,
      username: smtpTransport.username,
      password: smtpTransport.password,
      helo: smtpTransport.helo,
      mailFrom: resolveEnvelopeSender(settings, from),
      recipients,
      rawMessage: signed
    });
    finalizeSendEvent(eventId, user.id, {
      smtpRelayId: smtpTransport.smtpRelayId,
      status: 'queued',
      detail: smtpResult.message,
      queueId: smtpResult.queueId,
      deliveryLog: smtpResult.deliveryLog,
      trackingOpens: actualTracking.opens,
      trackingClicks: actualTracking.clicks
    });
    return {
      eventId,
      queued: true,
      domain: domain.domain,
      recipients,
      smtp: smtpResult.message,
      queueId: smtpResult.queueId,
      smtpRelayId: smtpTransport.smtpRelayId,
      tracking: actualTracking
    };
  } catch (error) {
    finalizeSendEvent(eventId, user.id, {
      smtpRelayId: smtpTransport.smtpRelayId,
      status: 'failed',
      detail: error.message,
      deliveryLog: deliveryLogFromError(error),
      trackingOpens: actualTracking.opens,
      trackingClicks: actualTracking.clicks
    });
    throw error;
  }
}

function resolveSendTracking(body, settings, recipients) {
  if (!body.html) return { enabled: false, opens: false, clicks: false, messageLevel: recipients.length > 1 };
  const configured = Boolean(settings.engagementTrackingEnabled);
  const requested = body.tracking;
  let opens = configured;
  let clicks = configured;
  if (typeof requested === 'boolean') {
    opens = requested;
    clicks = requested;
  } else if (requested && typeof requested === 'object') {
    if (Object.hasOwn(requested, 'opens')) opens = Boolean(requested.opens);
    if (Object.hasOwn(requested, 'clicks')) clicks = Boolean(requested.clicks);
  }
  return {
    enabled: opens || clicks,
    opens,
    clicks,
    messageLevel: recipients.length > 1
  };
}

function createTrackedClickUrl({ appBaseUrl, userId, eventId, target }) {
  const normalizedTarget = new URL(target).toString();
  const token = createTrackingToken();
  createTrackingLink(userId, eventId, {
    token,
    targetCiphertext: encryptTrackingTarget(normalizedTarget, envConfig.trackingSecret),
    targetFingerprint: trackingTargetFingerprint(normalizedTarget, envConfig.trackingSecret),
    targetOrigin: new URL(normalizedTarget).origin
  });
  return `${trackingUrlBase(appBaseUrl)}/t/c/${token}`;
}

function trackingOpenUrl(appBaseUrl, token) {
  return `${trackingUrlBase(appBaseUrl)}/t/o/${token}.gif`;
}

function trackingUrlBase(appBaseUrl) {
  return String(appBaseUrl || '').replace(/\/+$/, '');
}

function deliveryLogFromError(error) {
  if (Array.isArray(error?.deliveryLog)) return error.deliveryLog;
  return [{
    at: new Date().toISOString(),
    phase: 'error',
    direction: 'system',
    message: error?.message || 'Unknown SMTP delivery error',
    ok: false
  }];
}

function smtpTransportForSend(body, domain, user) {
  const requestedRelayId = Number(body.smtpRelayId || 0) || null;
  if (requestedRelayId) {
    const relay = getSmtpRelay(requestedRelayId, user.id, { includePassword: true });
    if (!relay) throw new Error('SMTP 出口不存在。');
    return smtpTransportFromRelay(relay);
  }
  if (domain.smtpRelayId) {
    const relay = getSmtpRelay(domain.smtpRelayId, user.id, { includePassword: true });
    if (!relay) throw new Error('SMTP 出口不存在。');
    return smtpTransportFromRelay(relay);
  }
  const defaultRelay = getDefaultSmtpRelay(user.id, { includePassword: true });
  if (defaultRelay) return smtpTransportFromRelay(defaultRelay);
  return {
    smtpRelayId: null,
    host: envConfig.smtpHost,
    port: envConfig.smtpPort,
    secure: envConfig.smtpSecure,
    username: envConfig.smtpUser,
    password: envConfig.smtpPassword,
    helo: envConfig.smtpHelo
  };
}

function smtpTransportFromRelay(relay) {
  return {
    smtpRelayId: relay.id,
    host: relay.host,
    port: relay.port,
    secure: relay.secure,
    username: relay.username,
    password: relay.password || '',
    helo: relay.helo || envConfig.smtpHelo
  };
}

function runBackground(promise) {
  promise.catch((error) => console.error(error));
}

async function handleRegister(req, res) {
  const body = await readJson(req);
  try {
    const { user, accountToken } = createUserWithAccountToken({
      username: body.username,
      email: body.email,
      password: body.password,
      status: 'pending_email'
    }, emailVerificationPurpose, { ttlMinutes: 24 * 60 });
    const emailResult = await sendVerificationEmail(user, accountToken.token);
    return sendRegisterSuccess(req, res, user, emailResult);
  } catch (error) {
    if (isUniqueError(error)) return sendAuthError(req, res, 409, '用户名或邮箱已被注册。', '/register');
    return sendAuthError(req, res, 400, error.message || '注册失败。', '/register');
  }
}

async function handleResendVerification(req, res) {
  const body = await readJson(req);
  const user = getUserByLogin(body.email);
  if (user?.status === 'pending_email') {
    runBackground(createAndSendVerificationEmail(user));
  }
  return sendJson(res, 202, publicVerificationResendResponse());
}

async function handleForgotPassword(req, res) {
  const body = await readJson(req);
  const user = getUserByLogin(body.email);
  if (user) runBackground(createAndSendPasswordResetEmail(user));
  return sendJson(res, 202, publicForgotPasswordResponse());
}

async function handleResetPassword(req, res) {
  const body = await readJson(req);
  if (String(body.password || '').length < 8) return sendJson(res, 400, { error: '密码至少需要 8 位。' });
  const consumed = consumeAccountToken(body.token, passwordResetPurpose);
  if (!consumed) return sendJson(res, 400, { error: '重置链接无效或已过期。' });
  updateUser(consumed.userId, { password: body.password });
  return sendJson(res, 200, { message: '密码已重置，请使用新密码登录。' });
}

async function handleVerifyEmail(req, res, url) {
  if ((req.method || 'GET') !== 'GET') return sendJson(res, 404, { error: 'Not found.' });
  const token = String(url.searchParams.get('token') || '').trim();
  if (!token) return sendJson(res, 400, { error: '验证链接无效或已过期。' });
  const consumed = consumeAccountToken(token, emailVerificationPurpose);
  if (!consumed) return sendJson(res, 400, { error: '验证链接无效或已过期。' });
  const user = markUserEmailVerified(consumed.userId);
  if (!user) return sendJson(res, 400, { error: '验证链接无效或已过期。' });
  return sendJson(res, 200, {
    user,
    message: '邮箱验证成功，请等待管理员审核。'
  });
}

async function createAndSendVerificationEmail(user) {
  const settings = systemMailSettingsForSend();
  if (!systemMailConfigured(settings)) return { ok: false, message: '系统邮件未配置。' };
  invalidateAccountTokens(user.id, emailVerificationPurpose);
  const accountToken = createAccountToken(user.id, emailVerificationPurpose, { ttlMinutes: 24 * 60 });
  const result = await sendVerificationEmailWithSettings(user, accountToken.token, settings);
  if (!result.ok) invalidateAccountTokens(user.id, emailVerificationPurpose);
  return result;
}

async function createAndSendPasswordResetEmail(user) {
  const settings = systemMailSettingsForSend();
  if (!systemMailConfigured(settings)) return { ok: false, message: '系统邮件未配置。' };
  invalidateAccountTokens(user.id, passwordResetPurpose);
  const accountToken = createAccountToken(user.id, passwordResetPurpose, { ttlMinutes: 60 });
  const result = await sendSystemEmail(settings, buildPasswordResetEmail({
    appBaseUrl: settings.appBaseUrl,
    to: user.email,
    token: accountToken.token,
    fromEmail: settings.fromEmail,
    fromName: settings.fromName
  }));
  if (!result.ok) invalidateAccountTokens(user.id, passwordResetPurpose);
  return result;
}

async function sendVerificationEmail(user, token) {
  const settings = systemMailSettingsForSend();
  if (!systemMailConfigured(settings)) {
    return { ok: false, message: '系统邮件未配置。' };
  }
  return await sendVerificationEmailWithSettings(user, token, settings);
}

async function sendVerificationEmailWithSettings(user, token, settings) {
  return await sendSystemEmail(settings, buildVerificationEmail({
    appBaseUrl: settings.appBaseUrl,
    to: user.email,
    token,
    fromEmail: settings.fromEmail,
    fromName: settings.fromName
  }));
}

function systemMailConfigured(settings) {
  return Boolean(settings.host && extractAddress(settings.fromEmail));
}

function systemMailSettingsForSend() {
  return {
    ...getSystemEmailSettings({ includeSecret: true }),
    appBaseUrl: runtimeSettings().appBaseUrl
  };
}

function publicVerificationResendResponse() {
  return {
    message: '如果账号需要验证，我们会发送验证邮件。'
  };
}

function publicForgotPasswordResponse() {
  return {
    message: '如果邮箱存在，我们会发送密码重置邮件。'
  };
}

function verificationEmailResponse(result) {
  return {
    verificationEmailSent: Boolean(result.ok),
    message: result.ok ? '验证邮件已发送。' : '验证邮件暂未发送，请稍后重试或联系管理员。',
    result: {
      ok: Boolean(result.ok),
      message: result.message || '',
      queueId: result.queueId || ''
    }
  };
}

async function handleLogin(req, res) {
  const body = await readJson(req);
  const user = verifyUserCredentials(body.username || body.email, body.password);
  if (!user) return sendAuthError(req, res, 401, '账号或密码不正确。', '/login');
  if (user.status !== 'active') return sendAuthError(req, res, 403, loginStatusMessage(user.status), '/login');
  return sendAuthSuccess(req, res, 200, user);
}

function sendRegisterSuccess(req, res, user, emailResult = { ok: false }) {
  const message = emailResult.ok
    ? '注册成功，验证邮件已发送，请先验证邮箱，验证后等待管理员审核。'
    : '注册成功，请先验证邮箱；验证邮件暂未发送，请联系管理员或稍后重试。';
  if (wantsHtmlRedirect(req)) return redirect(res, `/login?error=${encodeURIComponent(message)}`, 303);
  return sendJson(res, 201, {
    user,
    message,
    verificationEmailSent: Boolean(emailResult.ok)
  });
}

function sendAuthSuccess(req, res, status, user) {
  const token = createSessionToken(user);
  const cookie = sessionCookie(token);
  if (wantsHtmlRedirect(req)) return redirect(res, '/', 303, { 'Set-Cookie': cookie });
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Set-Cookie': cookie
  });
  res.end(JSON.stringify({ user }));
}

function sendAuthError(req, res, status, message, fallbackPath) {
  if (wantsHtmlRedirect(req)) return redirect(res, `${fallbackPath}?error=${encodeURIComponent(message)}`, 303);
  return sendJson(res, status, { error: message });
}

function loginStatusMessage(status) {
  if (status === 'pending_email') return '请先验证邮箱。';
  if (status === 'pending_review') return '账号正在等待管理员审核。';
  if (status === 'disabled') return '账号已被禁用。';
  return '账号或密码不正确。';
}

function handleLogout(res) {
  res.writeHead(200, {
    'Content-Type': 'application/json; charset=utf-8',
    'Set-Cookie': 'mailhub_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0'
  });
  res.end(JSON.stringify({ ok: true }));
}

function getRequestUser(req, pathname) {
  const sessionUser = getSessionUser(req);
  if (sessionUser) return sessionUser;
  const auth = req.headers.authorization || '';
  if (auth.startsWith('Basic ')) {
    const decoded = Buffer.from(auth.slice(6), 'base64').toString('utf8');
    const index = decoded.indexOf(':');
    const user = authenticateUser(decoded.slice(0, index), decoded.slice(index + 1));
    if (user) return user;
  }
  if (isTokenApiPath(pathname) && auth.startsWith('Bearer ')) {
    const token = auth.slice(7);
    const authenticated = authenticateApiToken(token);
    if (authenticated) {
      req.mailhubApiToken = authenticated.token;
      return authenticated.user;
    }
    if (pathname === '/api/send' && envConfig.legacyApiToken && safeEqual(token, envConfig.legacyApiToken)) {
      req.mailhubApiToken = { scopes: ['send'], tokenPrefix: 'legacy' };
      return getAdminUser();
    }
  }
  return null;
}

function isTokenApiPath(pathname) {
  return pathname === '/api/send' || pathname === '/api/mailboxes';
}

function requireApiTokenScope(req, res, scope) {
  const token = req.mailhubApiToken;
  if (!token || token.scopes?.includes(scope)) return true;
  sendJson(res, 403, { error: `当前 API Token 缺少 ${scope} 权限。` });
  return false;
}

function getSessionUser(req) {
  const token = parseCookies(req.headers.cookie || '').mailhub_session;
  if (!token || !token.includes('.')) return null;
  const [payload, signature] = token.split('.');
  if (!payload || !signature || !safeEqual(signature, signSessionPayload(payload))) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (Number(data.exp) <= Date.now()) return null;
    const user = getUser(Number(data.uid));
    return user?.status === 'active' ? user : null;
  } catch {
    return null;
  }
}

function createSessionToken(user) {
  const payload = Buffer.from(JSON.stringify({
    uid: user.id,
    exp: Date.now() + 12 * 60 * 60 * 1000,
    nonce: crypto.randomBytes(10).toString('hex')
  })).toString('base64url');
  return `${payload}.${signSessionPayload(payload)}`;
}

function signSessionPayload(payload) {
  return crypto.createHmac('sha256', envConfig.sessionSecret).update(payload).digest('base64url');
}

function sessionCookie(token) {
  return [`mailhub_session=${token}`, 'Path=/', 'HttpOnly', 'SameSite=Lax', 'Max-Age=43200'].join('; ');
}

function publicConfig(user) {
  const settings = runtimeSettings();
  const smtpCredential = getSmtpCredential(user.id);
  return {
    ...settings,
    smtpHost: envConfig.smtpHost ? 'configured' : '',
    submission: {
      enabled: envConfig.submissionEnabled,
      host: envConfig.submissionHost,
      ports: publicSubmissionListeners(envConfig.submissionListeners),
      username: smtpCredential?.username || '',
      passwordSet: Boolean(smtpCredential?.passwordSet),
      inboundEnabled: envConfig.inboundEnabled,
      tls: Boolean(envConfig.submissionTlsCert && envConfig.submissionTlsKey),
      requireTlsForAuth: !envConfig.submissionAllowInsecureAuth
    },
    mailAccess: {
      host: envConfig.submissionHost,
      tls: Boolean(envConfig.submissionTlsCert && envConfig.submissionTlsKey),
      requireTlsForAuth: !envConfig.mailboxAccessAllowInsecureAuth,
      imap: {
        enabled: envConfig.imapEnabled,
        ports: publicMailboxAccessListeners(envConfig.imapListeners, {
          tls: Boolean(envConfig.submissionTlsCert && envConfig.submissionTlsKey)
        })
      },
      pop3: {
        enabled: envConfig.pop3Enabled,
        ports: publicMailboxAccessListeners(envConfig.pop3Listeners, {
          tls: Boolean(envConfig.submissionTlsCert && envConfig.submissionTlsKey)
        })
      }
    },
    apiTokenSet: Boolean(envConfig.legacyApiToken),
    usingDefaultAdminPassword: user.role === 'admin' && envConfig.adminPassword === 'change-this-admin-password'
  };
}

function runtimeSettings() {
  const settings = getSettings(defaultSettings);
  return {
    appBaseUrl: settings.appBaseUrl,
    mailHostname: settings.mailHostname,
    sendingIp: settings.sendingIp,
    defaultSpfMechanisms: settings.defaultSpfMechanisms,
    dmarcPolicy: normalizeDmarcPolicy(settings.dmarcPolicy),
    dmarcRua: settings.dmarcRua,
    sendRequiresVerified: String(settings.sendRequiresVerified).toLowerCase() === 'true',
    engagementTrackingEnabled: String(settings.engagementTrackingEnabled).toLowerCase() === 'true',
    listUnsubscribeMailto: settings.listUnsubscribeMailto,
    listUnsubscribeUrl: settings.listUnsubscribeUrl,
    listUnsubscribePostEnabled: String(settings.listUnsubscribePostEnabled).toLowerCase() === 'true',
    feedbackIdEnabled: String(settings.feedbackIdEnabled).toLowerCase() !== 'false',
    reportAbuseTo: settings.reportAbuseTo,
    csaComplaintsTo: settings.csaComplaintsTo,
    bounceAddress: settings.bounceAddress,
    bounceEnvelopeEnabled: String(settings.bounceEnvelopeEnabled).toLowerCase() === 'true'
  };
}

async function adminRuntimeSettings() {
  const settings = runtimeSettings();
  return {
    ...settings,
    systemChecks: await buildSystemDnsChecks(settings)
  };
}

async function serveStatic(req, res, url) {
  const publicDir = path.join(__dirname, '..', 'public');
  const pathname = decodeURIComponent(resolveStaticPathname(url.pathname));
  const filePath = path.normalize(path.join(publicDir, pathname));
  if (!filePath.startsWith(publicDir) || !existsSync(filePath) || statSync(filePath).isDirectory()) {
    return sendStaticFile(res, path.join(publicDir, 'index.html'), { noStore: true });
  }
  const noStore = path.extname(filePath) === '.html';
  return sendStaticFile(res, filePath, { noStore });
}

async function sendStaticFile(res, filePath, { noStore = false } = {}) {
  const ext = path.extname(filePath);
  const contentType = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.svg': 'image/svg+xml'
  }[ext] || 'application/octet-stream';
  const headers = { 'Content-Type': contentType };
  if (noStore || ext === '.html') {
    headers['Cache-Control'] = 'private, no-store';
  }
  res.writeHead(200, headers);
  res.end(await readFile(filePath));
}

async function readJson(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  if (!chunks.length) return {};
  const raw = Buffer.concat(chunks).toString('utf8');
  const contentType = String(req.headers['content-type'] || '').toLowerCase();
  if (contentType.includes('application/x-www-form-urlencoded')) {
    return Object.fromEntries(new URLSearchParams(raw).entries());
  }
  return JSON.parse(raw);
}

const trackingPixel = Buffer.from(
  'R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7',
  'base64'
);

async function handleTrackingRequest(req, res, url) {
  const openMatch = url.pathname.match(/^\/t\/o\/([A-Za-z0-9_-]{20,128})\.gif$/);
  if (openMatch) {
    if (!['GET', 'HEAD'].includes(req.method)) return sendTrackingStatus(res, 405, 'Method not allowed.');
    if (req.method === 'GET') {
      const sendEvent = findSendEventByTrackingToken(openMatch[1]);
      if (sendEvent?.tracking?.opens) {
        recordPublicTrackingEvent(req, {
          sendEvent,
          eventType: 'open'
        });
      }
    }
    return sendTrackingPixel(res, req.method === 'HEAD');
  }
  if (url.pathname.startsWith('/t/o/')) {
    if (!['GET', 'HEAD'].includes(req.method)) return sendTrackingStatus(res, 405, 'Method not allowed.');
    return sendTrackingPixel(res, req.method === 'HEAD');
  }

  const clickMatch = url.pathname.match(/^\/t\/c\/([A-Za-z0-9_-]{20,128})$/);
  if (!clickMatch) {
    if (url.pathname.startsWith('/t/c/')) return sendTrackingStatus(res, 404, 'Not found.');
    return false;
  }
  if (req.method !== 'GET') return sendTrackingStatus(res, 405, 'Method not allowed.');
  const link = findTrackingLinkByToken(clickMatch[1]);
  if (!link?.trackingClicks) return sendTrackingStatus(res, 404, 'Not found.');
  let target;
  try {
    target = decryptTrackingTarget(link.targetCiphertext, envConfig.trackingSecret);
  } catch {
    return sendTrackingStatus(res, 410, 'Link is no longer available.');
  }
  recordPublicTrackingEvent(req, {
    sendEvent: {
      id: link.sendEventId,
      userId: link.userId
    },
    eventType: 'click',
    trackingLinkId: link.id
  });
  res.writeHead(302, {
    Location: target,
    'Cache-Control': 'private, no-store, no-cache, max-age=0',
    Pragma: 'no-cache',
    'Referrer-Policy': 'no-referrer'
  });
  res.end();
  return true;
}

function recordPublicTrackingEvent(req, { sendEvent, eventType, trackingLinkId = null }) {
  const occurredAt = new Date().toISOString();
  const userAgent = String(req.headers['user-agent'] || '').slice(0, 500);
  const source = classifyTrackingSource(userAgent);
  const ipHash = hashTrackingClientIp({
    ip: requestClientIp(req),
    secret: envConfig.trackingSecret,
    userId: sendEvent.userId,
    sendEventId: sendEvent.id,
    occurredAt
  });
  const replayKey = trackingReplayKey({
    secret: envConfig.trackingSecret,
    sendEventId: sendEvent.id,
    eventType,
    trackingLinkId,
    ipHash,
    userAgent,
    occurredAt
  });
  try {
    recordTrackingEvent({
      sendEventId: sendEvent.id,
      trackingLinkId,
      eventType,
      source,
      occurredAt,
      userAgent,
      ipHash,
      replayKey
    });
  } catch (error) {
    console.warn(`Tracking event could not be recorded: ${error.message}`);
  }
}

function requestClientIp(req) {
  if (envConfig.trustProxy) {
    const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    if (forwarded) return forwarded;
  }
  return req.socket?.remoteAddress || '';
}

function sendTrackingPixel(res, headOnly = false) {
  res.writeHead(200, {
    'Content-Type': 'image/gif',
    'Content-Length': String(trackingPixel.length),
    'Cache-Control': 'private, no-store, no-cache, max-age=0',
    Pragma: 'no-cache',
    Expires: '0',
    'Referrer-Policy': 'no-referrer'
  });
  res.end(headOnly ? undefined : trackingPixel);
  return true;
}

function sendTrackingStatus(res, status, message) {
  res.writeHead(status, {
    'Content-Type': 'text/plain; charset=utf-8',
    'Cache-Control': 'private, no-store, no-cache, max-age=0',
    Pragma: 'no-cache',
    'Referrer-Policy': 'no-referrer'
  });
  res.end(message);
  return true;
}

function sendJson(res, status, payload) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(payload));
}

function redirect(res, location, status = 302, headers = {}) {
  res.writeHead(status, { ...headers, Location: location });
  res.end();
}

function wantsHtmlRedirect(req) {
  const contentType = String(req.headers['content-type'] || '').toLowerCase();
  const accept = String(req.headers.accept || '').toLowerCase();
  return contentType.includes('application/x-www-form-urlencoded') && accept.includes('text/html');
}

function setSecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
}

function handleOptions(res) {
  res.writeHead(204, {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
  });
  res.end();
}

function parseCookies(header) {
  const cookies = {};
  for (const part of String(header || '').split(';')) {
    const index = part.indexOf('=');
    if (index === -1) continue;
    cookies[part.slice(0, index).trim()] = part.slice(index + 1).trim();
  }
  return cookies;
}

function safeEqual(actual, expected) {
  const a = Buffer.from(String(actual || ''));
  const b = Buffer.from(String(expected || ''));
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function normalizeDomain(input) {
  const raw = String(input || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/\.$/, '');
  const ascii = domainToASCII(raw);
  if (!ascii || ascii.length > 253) return '';
  if (!/^(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$/.test(ascii)) return '';
  return ascii;
}

function normalizeHostname(input) {
  return normalizeDomain(input) || String(input || '').trim().toLowerCase();
}

function normalizeSelector(input) {
  const value = String(input || '').trim().toLowerCase();
  return /^[a-z0-9][a-z0-9-]{0,62}$/.test(value) ? value : '';
}

function normalizeDmarcPolicy(input) {
  const value = String(input || '').trim().toLowerCase();
  return ['none', 'quarantine', 'reject'].includes(value) ? value : 'none';
}

function smtpRelayPatch(body) {
  const patch = {};
  for (const key of ['name', 'host', 'port', 'secure', 'username', 'password', 'helo', 'isDefault']) {
    if (Object.hasOwn(body, key)) patch[key] = body[key];
  }
  return patch;
}

function mailboxApiRequest(body) {
  const mode = normalizeMailboxApiMode(body.mode);
  if (!mode) throw new Error('邮箱类型必须为 permanent 或 temporary。');
  const address = resolveMailboxApiAddress(body, mode);
  const password = String(body.password || '') || crypto.randomBytes(18).toString('base64url');
  if (password.length < 8) throw new Error('邮箱密码至少需要 8 位。');
  const expiresAt = mode === 'temporary' ? temporaryMailboxExpiresAt(body.expiresInMinutes) : null;
  return {
    mode,
    password,
    mailbox: {
      address,
      password,
      displayName: body.displayName,
      aliases: body.aliases,
      forwardTo: body.forwardTo,
      keepForwarded: body.keepForwarded,
      quotaMb: body.quotaMb,
      expiresAt
    }
  };
}

function normalizeMailboxApiMode(value) {
  const mode = String(value || 'permanent').trim().toLowerCase();
  if (['permanent', 'long'].includes(mode)) return 'permanent';
  if (['temporary', 'temp'].includes(mode)) return 'temporary';
  return '';
}

function resolveMailboxApiAddress(body, mode) {
  const address = String(body.address || '').trim().toLowerCase();
  if (address) return address;
  const domain = normalizeDomain(body.domain);
  if (!domain) throw new Error('请提供已添加域名的 address，或提供有效的 domain。');
  const specifiedLocalPart = String(body.localPart || '').trim().toLowerCase();
  const localPart = specifiedLocalPart || (mode === 'temporary' ? `tmp-${crypto.randomBytes(7).toString('hex')}` : '');
  if (!localPart || !/^[^@\s]+$/.test(localPart)) throw new Error('邮箱 localPart 格式不正确。');
  return `${localPart}@${domain}`;
}

function temporaryMailboxExpiresAt(value) {
  const minutes = Number(value);
  const maxMinutes = 30 * 24 * 60;
  if (!Number.isInteger(minutes) || minutes < 5 || minutes > maxMinutes) {
    throw new Error(`临时邮箱 expiresInMinutes 必须是 5 到 ${maxMinutes} 分钟之间的整数。`);
  }
  return new Date(Date.now() + minutes * 60 * 1000).toISOString();
}

function inboundMailboxPatch(body) {
  const patch = {};
  for (const key of ['address', 'displayName', 'password', 'aliases', 'forwardTo', 'keepForwarded', 'quotaMb', 'status']) {
    if (Object.hasOwn(body, key)) patch[key] = body[key];
  }
  return patch;
}

function normalizeCatchAllAddress(value) {
  const clean = String(value || '').trim().toLowerCase();
  if (!clean) return '';
  if (clean === '/dev/null') return clean;
  return extractAddress(clean);
}

function mailboxClientConfig(mailbox, { password = '' } = {}) {
  const smtpPort = preferredSubmissionPort(['SMTP + STARTTLS', 'SMTPS']);
  const imapPort = preferredMailboxAccessPort(envConfig.imapListeners, ['IMAPS', 'IMAP + STARTTLS', 'IMAP']);
  const pop3Port = preferredMailboxAccessPort(envConfig.pop3Listeners, ['POP3S', 'POP3 + STLS', 'POP3']);
  return {
    username: mailbox.address,
    password,
    incoming: {
      protocol: 'IMAP',
      host: envConfig.submissionHost,
      port: imapPort?.port || 143,
      security: imapPort?.protocol || 'IMAP + STARTTLS',
      authMethod: 'Normal password',
      username: mailbox.address,
      password
    },
    pop3: {
      protocol: 'POP3',
      host: envConfig.submissionHost,
      port: pop3Port?.port || 110,
      security: pop3Port?.protocol || 'POP3 + STLS',
      authMethod: 'Normal password',
      username: mailbox.address,
      password
    },
    outgoing: {
      protocol: 'SMTP',
      host: envConfig.submissionHost,
      port: smtpPort?.port || 587,
      security: smtpPort?.protocol || 'SMTP + STARTTLS',
      authMethod: 'Normal password',
      username: mailbox.address,
      password
    }
  };
}

function preferredMailboxAccessPort(listeners, protocols) {
  const tlsEnabled = Boolean(envConfig.submissionTlsCert && envConfig.submissionTlsKey);
  const publicListeners = publicMailboxAccessListeners(listeners, { tls: tlsEnabled });
  for (const protocol of protocols) {
    const match = publicListeners.find((listener) => listener.protocol === protocol && [993, 995].includes(listener.port)) ||
      publicListeners.find((listener) => listener.protocol === protocol);
    if (match) return match;
  }
  return publicListeners[0] || null;
}

function preferredSubmissionPort(protocols) {
  const listeners = publicSubmissionListeners(envConfig.submissionListeners);
  for (const protocol of protocols) {
    const match = listeners.find((listener) => listener.protocol === protocol && listener.port === 587) ||
      listeners.find((listener) => listener.protocol === protocol && listener.port === 465) ||
      listeners.find((listener) => listener.protocol === protocol);
    if (match) return match;
  }
  return listeners[0] || null;
}

function settingsPatchFromBody(body) {
  const patch = {};
  for (const key of [
    'appBaseUrl',
    'mailHostname',
    'sendingIp',
    'defaultSpfMechanisms',
    'dmarcRua',
    'listUnsubscribeMailto',
    'listUnsubscribeUrl',
    'reportAbuseTo',
    'csaComplaintsTo',
    'bounceAddress'
  ]) {
    if (Object.hasOwn(body, key)) patch[key] = body[key];
  }
  if (Object.hasOwn(body, 'dmarcPolicy')) patch.dmarcPolicy = normalizeDmarcPolicy(body.dmarcPolicy);
  if (Object.hasOwn(body, 'sendRequiresVerified')) patch.sendRequiresVerified = boolString(body.sendRequiresVerified);
  if (Object.hasOwn(body, 'engagementTrackingEnabled')) {
    patch.engagementTrackingEnabled = boolString(body.engagementTrackingEnabled);
  }
  if (Object.hasOwn(body, 'listUnsubscribePostEnabled')) {
    patch.listUnsubscribePostEnabled = boolString(body.listUnsubscribePostEnabled);
  }
  if (Object.hasOwn(body, 'feedbackIdEnabled')) {
    patch.feedbackIdEnabled = boolString(body.feedbackIdEnabled);
  }
  if (Object.hasOwn(body, 'bounceEnvelopeEnabled')) {
    patch.bounceEnvelopeEnabled = boolString(body.bounceEnvelopeEnabled);
  }
  return patch;
}

function boolString(value) {
  return String(value).toLowerCase() === 'true' || value === true ? 'true' : 'false';
}

function defaultSelector() {
  const d = new Date();
  return `mh${d.getUTCFullYear()}${String(d.getUTCMonth() + 1).padStart(2, '0')}`;
}

async function buildDnsGuideAfterApply(domain, applyResult) {
  const appliedKeys = new Set((applyResult.results || [])
    .filter((result) => result.ok && !result.skipped)
    .map((result) => result.key));
  let guide = await buildDnsGuide(domain);
  for (let attempt = 0; attempt < 2 && hasUnpropagatedAppliedRecords(guide, appliedKeys); attempt += 1) {
    await sleep(1800);
    guide = await buildDnsGuide(domain);
  }
  return markUnpropagatedAppliedRecords(guide, appliedKeys);
}

function hasUnpropagatedAppliedRecords(guide, appliedKeys) {
  return (guide.records || []).some((record) => appliedKeys.has(record.key) && record.status !== 'ok');
}

function markUnpropagatedAppliedRecords(guide, appliedKeys) {
  const records = (guide.records || []).map((record) => {
    if (!appliedKeys.has(record.key) || record.status === 'ok') return record;
    return {
      ...record,
      status: 'pending',
      warnings: [
        ...(record.warnings || []),
        '已提交到 DNS 服务商，正在等待公共 DNS 传播；稍后点击“立即检查”刷新。'
      ]
    };
  });
  return {
    ...guide,
    records,
    warnings: collectGuideWarnings(records)
  };
}

function collectGuideWarnings(records) {
  return records.flatMap((record) => record.warnings || []);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isUniqueError(error) {
  return /UNIQUE constraint failed/i.test(String(error?.message || ''));
}

function isLoginAsset(pathname) {
  return pathname.startsWith('/assets/')
    || [
      '/login',
      '/register',
      '/forgot-password',
      '/resend-verification',
      '/reset-password',
      '/login.html',
      '/login.css',
      '/login.js',
      '/landing.html'
    ].includes(pathname);
}

function resolveStaticPathname(pathname) {
  if (pathname === '/') return '/landing.html';
  if (['/login', '/register', '/forgot-password', '/resend-verification', '/reset-password'].includes(pathname)) return '/login.html';
  return pathname;
}

function loadDotEnv() {
  const file = path.join(process.cwd(), '.env');
  if (!existsSync(file)) return;
  const lines = readFileSync(file, 'utf8').split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const index = trimmed.indexOf('=');
    if (index === -1) continue;
    const key = trimmed.slice(0, index).trim();
    let value = trimmed.slice(index + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    if (!(key in process.env)) process.env[key] = value;
  }
}
