import crypto from 'node:crypto';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath, domainToASCII } from 'node:url';
import {
  authenticateUser,
  claimLegacyData,
  createApiToken,
  createDomain,
  createUser,
  deleteApiToken,
  deleteDnsCredential,
  deleteDomain,
  getAdminUser,
  getDnsCredential,
  getDomain,
  getDomainByName,
  getSendAnalytics,
  getSettings,
  getSmtpCredential,
  getUser,
  initDatabase,
  listApiTokens,
  listDnsCredentials,
  listDomains,
  listSendEvents,
  listUsers,
  logSendEvent,
  saveDnsCredential,
  saveDomainStatus,
  saveSettings,
  saveSmtpCredential,
  seedAdminUser,
  seedSmtpCredential,
  updateDkim,
  updateDomain,
  updateUser,
  verifyApiToken
} from './db.js';
import { applyDnsSetup, testDnsCredential } from './dns-providers.js';
import { startPostfixDeliveryTracker } from './delivery-tracker.js';
import { buildDnsGuide } from './dns-guide.js';
import { createDkimKeyPair } from './dkim.js';
import {
  buildMessage,
  domainFromAddress,
  extractAddress,
  parseAddressList,
  sendViaSmtp,
  signMessageForDomain
} from './mailer.js';
import {
  parseSubmissionListeners,
  publicSubmissionListeners,
  startSubmissionServer
} from './submission.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
loadDotEnv();

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
  submissionEnabled: String(process.env.SUBMISSION_ENABLED || 'true').toLowerCase() !== 'false',
  submissionHost: process.env.SUBMISSION_HOST || process.env.APP_BASE_URL?.replace(/^https?:\/\//, '') || 'localhost',
  submissionListeners: parseSubmissionListeners(process.env.SUBMISSION_PORTS),
  submissionUsername: process.env.SUBMISSION_USERNAME || '',
  submissionPassword: process.env.SUBMISSION_PASSWORD || '',
  submissionAllowInsecureAuth: String(process.env.SUBMISSION_ALLOW_INSECURE_AUTH || '').toLowerCase() === 'true',
  submissionTlsCert: process.env.SUBMISSION_TLS_CERT || '',
  submissionTlsKey: process.env.SUBMISSION_TLS_KEY || '',
  sessionSecret: process.env.SESSION_SECRET || crypto
    .createHash('sha256')
    .update(`${process.env.ADMIN_PASSWORD || 'change-this-admin-password'}:${process.env.API_TOKEN || ''}`)
    .digest('hex')
};

const defaultSettings = {
  appBaseUrl: process.env.APP_BASE_URL || 'http://127.0.0.1:3000',
  mailHostname: process.env.MAIL_HOSTNAME || 'mailhub.local',
  sendingIp: process.env.SENDING_IP || '',
  defaultSpfMechanisms: process.env.DEFAULT_SPF_MECHANISMS || 'include:spf.mailjet.com',
  dmarcPolicy: process.env.DMARC_POLICY || 'none',
  dmarcRua: process.env.DMARC_RUA || '',
  sendRequiresVerified: String(process.env.SEND_REQUIRES_VERIFIED || '').toLowerCase() === 'true' ? 'true' : 'false'
};

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

const server = http.createServer(async (req, res) => {
  try {
    setSecurityHeaders(res);
    if (req.method === 'OPTIONS') return handleOptions(res);
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    if (url.pathname === '/healthz') return sendJson(res, 200, { ok: true });
    if (req.method === 'POST' && (url.pathname === '/api/register' || url.pathname === '/register')) return await handleRegister(req, res);
    if (req.method === 'POST' && (url.pathname === '/api/login' || url.pathname === '/login')) return await handleLogin(req, res);
    if (req.method === 'POST' && url.pathname === '/api/logout') return handleLogout(res);

    const user = getRequestUser(req, url.pathname);
    if (isLoginAsset(url.pathname)) {
      if ((url.pathname === '/login' || url.pathname === '/register') && url.search) {
        return redirect(res, url.pathname);
      }
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
  tlsCertPath: envConfig.submissionTlsCert,
  tlsKeyPath: envConfig.submissionTlsKey,
  relayHost: envConfig.smtpHost,
  relayPort: envConfig.smtpPort,
  relaySecure: envConfig.smtpSecure,
  relayUsername: envConfig.smtpUser,
  relayPassword: envConfig.smtpPassword,
  relayHelo: envConfig.smtpHelo
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
    const keys = createDkimKeyPair();
    try {
      const row = createDomain(user.id, {
        domain,
        selector,
        dnsCredentialId,
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
  if (method === 'GET' && pathname === '/api/analytics') {
    return sendJson(res, 200, { analytics: getSendAnalytics(user.id, { days: Number(url.searchParams.get('days') || 30) }) });
  }
  if (method === 'GET' && pathname === '/api/smtp-credential') {
    return sendJson(res, 200, { credential: getSmtpCredential(user.id, { includePassword: true }) });
  }
  if ((method === 'POST' || method === 'PUT' || method === 'PATCH') && pathname === '/api/smtp-credential') {
    const body = await readJson(req);
    try {
      saveSmtpCredential(user.id, {
        username: String(body.username || '').trim(),
        password: String(body.password || '')
      });
    } catch (error) {
      if (isUniqueError(error)) return sendJson(res, 409, { error: 'SMTP 用户名已被占用。' });
      throw error;
    }
    return sendJson(res, 200, { credential: getSmtpCredential(user.id, { includePassword: true }) });
  }
  if (method === 'POST' && pathname === '/api/send') {
    const body = await readJson(req);
    const result = await sendMailFromBody(body, user);
    return sendJson(res, 202, result);
  }

  if (method === 'GET' && pathname === '/api/api-tokens') {
    return sendJson(res, 200, { tokens: listApiTokens(user.id) });
  }
  if (method === 'POST' && pathname === '/api/api-tokens') {
    const body = await readJson(req);
    return sendJson(res, 201, { token: createApiToken(user.id, body.name) });
  }
  const tokenMatch = pathname.match(/^\/api\/api-tokens\/(\d+)$/);
  if (tokenMatch && method === 'DELETE') {
    const deleted = deleteApiToken(Number(tokenMatch[1]), user.id);
    return sendJson(res, deleted ? 200 : 404, { deleted });
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

  if (pathname.startsWith('/api/admin/')) {
    return await handleAdminApi(req, res, pathname, method, user);
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
      const row = updateDomain(id, user.id, {
        selector: body.selector ? normalizeSelector(body.selector) : undefined,
        dnsCredentialId,
        senderHost: body.senderHost ? normalizeHostname(body.senderHost) : undefined,
        sendingIp: body.sendingIp !== undefined ? String(body.sendingIp).trim() : undefined,
        spfExtra: body.spfExtra !== undefined ? String(body.spfExtra).trim() : undefined,
        dmarcPolicy: body.dmarcPolicy ? normalizeDmarcPolicy(body.dmarcPolicy) : undefined,
        dmarcRua: body.dmarcRua !== undefined ? String(body.dmarcRua).trim() : undefined
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
      const from = body.from || `noreply@${row.domain}`;
      const result = await sendMailFromBody({
        from,
        to: body.to,
        subject: body.subject || `MailHub test for ${row.domain}`,
        text: body.text || `This is a MailHub test message from ${row.domain}.`
      }, user);
      return sendJson(res, 202, result);
    }
  }

  return sendJson(res, 404, { error: 'Not found.' });
}

async function handleAdminApi(req, res, pathname, method, user) {
  if (!pathname.startsWith('/api/admin/')) return null;
  if (user.role !== 'admin') return sendJson(res, 403, { error: '需要管理员权限。' });
  if (method === 'GET' && pathname === '/api/admin/settings') {
    return sendJson(res, 200, { settings: runtimeSettings() });
  }
  if ((method === 'PATCH' || method === 'PUT') && pathname === '/api/admin/settings') {
    const body = await readJson(req);
    saveSettings({
      appBaseUrl: body.appBaseUrl,
      mailHostname: body.mailHostname,
      sendingIp: body.sendingIp,
      defaultSpfMechanisms: body.defaultSpfMechanisms,
      dmarcPolicy: normalizeDmarcPolicy(body.dmarcPolicy),
      dmarcRua: body.dmarcRua,
      sendRequiresVerified: boolString(body.sendRequiresVerified)
    });
    return sendJson(res, 200, { settings: runtimeSettings() });
  }
  if (method === 'GET' && pathname === '/api/admin/users') {
    return sendJson(res, 200, { users: listUsers() });
  }
  const userMatch = pathname.match(/^\/api\/admin\/users\/(\d+)$/);
  if (userMatch && method === 'PATCH') {
    const body = await readJson(req);
    const updated = updateUser(Number(userMatch[1]), {
      role: body.role,
      status: body.status,
      password: body.password
    });
    return sendJson(res, updated ? 200 : 404, { user: updated });
  }
  return sendJson(res, 404, { error: 'Not found.' });
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

  const rawMessage = buildMessage({
    from,
    to: recipients,
    subject: body.subject || '(no subject)',
    text: body.text || '',
    html: body.html || '',
    baseUrl: settings.appBaseUrl
  });
  const signed = signMessageForDomain(rawMessage, domain);
  try {
    const smtpResult = await sendViaSmtp({
      host: envConfig.smtpHost,
      port: envConfig.smtpPort,
      secure: envConfig.smtpSecure,
      username: envConfig.smtpUser,
      password: envConfig.smtpPassword,
      helo: envConfig.smtpHelo,
      mailFrom: from,
      recipients,
      rawMessage: signed
    });
    logSendEvent({
      userId: user.id,
      domainId: domain.id,
      sender: from,
      recipients,
      subject: body.subject || '(no subject)',
      status: 'queued',
      detail: smtpResult.message,
      queueId: smtpResult.queueId,
      deliveryLog: smtpResult.deliveryLog
    });
    return { queued: true, domain: domain.domain, recipients, smtp: smtpResult.message, queueId: smtpResult.queueId };
  } catch (error) {
    logSendEvent({
      userId: user.id,
      domainId: domain.id,
      sender: from,
      recipients,
      subject: body.subject || '(no subject)',
      status: 'failed',
      detail: error.message,
      deliveryLog: deliveryLogFromError(error)
    });
    throw error;
  }
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

async function handleRegister(req, res) {
  const body = await readJson(req);
  try {
    const user = createUser({
      username: body.username,
      email: body.email,
      password: body.password
    });
    return sendAuthSuccess(req, res, 201, user);
  } catch (error) {
    if (isUniqueError(error)) return sendAuthError(req, res, 409, '用户名或邮箱已被注册。', '/register');
    return sendAuthError(req, res, 400, error.message || '注册失败。', '/register');
  }
}

async function handleLogin(req, res) {
  const body = await readJson(req);
  const user = authenticateUser(body.username || body.email, body.password);
  if (!user) return sendAuthError(req, res, 401, '账号或密码不正确。', '/login');
  return sendAuthSuccess(req, res, 200, user);
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
  if (pathname === '/api/send' && auth.startsWith('Bearer ')) {
    const token = auth.slice(7);
    const user = verifyApiToken(token);
    if (user) return user;
    if (envConfig.legacyApiToken && safeEqual(token, envConfig.legacyApiToken)) return getAdminUser();
  }
  return null;
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
      tls: Boolean(envConfig.submissionTlsCert && envConfig.submissionTlsKey),
      requireTlsForAuth: !envConfig.submissionAllowInsecureAuth
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
    sendRequiresVerified: String(settings.sendRequiresVerified).toLowerCase() === 'true'
  };
}

async function serveStatic(req, res, url) {
  const publicDir = path.join(__dirname, '..', 'public');
  const pathname = decodeURIComponent(resolveStaticPathname(url.pathname));
  const filePath = path.normalize(path.join(publicDir, pathname));
  if (!filePath.startsWith(publicDir) || !existsSync(filePath) || statSync(filePath).isDirectory()) {
    return sendStaticFile(res, path.join(publicDir, 'index.html'));
  }
  return sendStaticFile(res, filePath);
}

async function sendStaticFile(res, filePath) {
  const ext = path.extname(filePath);
  const contentType = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.svg': 'image/svg+xml'
  }[ext] || 'application/octet-stream';
  res.writeHead(200, { 'Content-Type': contentType });
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
    || ['/login', '/register', '/login.html', '/login.css', '/login.js'].includes(pathname);
}

function resolveStaticPathname(pathname) {
  if (pathname === '/') return '/index.html';
  if (pathname === '/login' || pathname === '/register') return '/login.html';
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
