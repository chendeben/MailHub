import net from 'node:net';
import tls from 'node:tls';
import { readFileSync } from 'node:fs';
import {
  createSendEvent,
  createInboundMessage,
  createTrackingLink,
  enqueueInboundWebhookDeliveries,
  finalizeSendEvent,
  getDomainByName,
  logSendEvent,
  resolveInboundRecipient,
  verifySmtpCredential
} from './db.js';
import { parseInboundMessage } from './inbound-mail.js';
import {
  addHeadersToRawMessage,
  buildDeliverabilityHeaders,
  createFeedbackId,
  domainFromAddress,
  extractAddress,
  resolveEnvelopeSender,
  sendViaSmtp,
  signMessageForDomain
} from './mailer.js';
import {
  createTrackingToken,
  encryptTrackingTarget,
  instrumentRawMime,
  stripRawMimeHeaders,
  trackingTargetFingerprint
} from './tracking.js';

const implicitTlsDetectTimeoutMs = 300;
const defaultMaxMessageBytes = 50 * 1024 * 1024;

export function startSubmissionServer(config) {
  if (!config.enabled) return null;
  const tlsMaterial = loadTlsMaterial(config);
  const servers = [];
  for (const listener of config.listeners) {
    const listenerConfig = {
      ...config,
      port: listener.port,
      protocol: listener.protocol,
      secureContext: tlsMaterial?.secureContext || null,
      tlsActive: listener.protocol === 'smtps',
      startTlsAvailable: listener.protocol === 'smtp' && Boolean(tlsMaterial?.secureContext)
    };
    const server = listener.protocol === 'smtps'
      ? tls.createServer({ key: tlsMaterial?.key, cert: tlsMaterial?.cert }, (socket) => new SubmissionSession(socket, listenerConfig))
      : net.createServer((socket) => acceptSubmissionSocket(socket, listenerConfig));
    server.listen(listener.port, '0.0.0.0', () => {
      console.log(`MailHub SMTP ${listener.protocol} listening on 0.0.0.0:${listener.port}`);
    });
    servers.push(server);
  }
  return servers;
}

export function resolveSubmissionTracking(rawMessage, defaultEnabled = false) {
  const control = extractHeader(String(rawMessage || ''), 'x-mailhub-track').trim().toLowerCase();
  if (!control) {
    const enabled = Boolean(defaultEnabled);
    return { enabled, opens: enabled, clicks: enabled, explicit: false };
  }
  if (['off', 'false', 'none', '0'].includes(control)) {
    return { enabled: false, opens: false, clicks: false, explicit: true };
  }
  const values = new Set(control.split(/[\s,]+/).filter(Boolean));
  const opens = values.has('open') || values.has('opens');
  const clicks = values.has('click') || values.has('clicks');
  return { enabled: opens || clicks, opens, clicks, explicit: true };
}

function createSubmissionClickUrl({ appBaseUrl, secret, userId, eventId, target }) {
  const normalizedTarget = new URL(target).toString();
  const token = createTrackingToken();
  createTrackingLink(userId, eventId, {
    token,
    targetCiphertext: encryptTrackingTarget(normalizedTarget, secret),
    targetFingerprint: trackingTargetFingerprint(normalizedTarget, secret),
    targetOrigin: new URL(normalizedTarget).origin
  });
  return `${trackingUrlBase(appBaseUrl)}/t/c/${token}`;
}

function trackingUrlBase(value) {
  return String(value || '').replace(/\/+$/, '');
}

function loadTlsMaterial(config) {
  if (!config.tlsKeyPath || !config.tlsCertPath) {
    console.warn('SMTP TLS certificate paths are not configured; STARTTLS/SMTPS will be unavailable.');
    return null;
  }
  try {
    const key = readFileSync(config.tlsKeyPath);
    const cert = readFileSync(config.tlsCertPath);
    return tls.createSecureContext({
      key,
      cert
    }) && {
      key,
      cert,
      secureContext: tls.createSecureContext({ key, cert })
    };
  } catch (error) {
    console.warn(`Unable to load SMTP TLS certificate: ${error.message}`);
    return null;
  }
}

function acceptSubmissionSocket(socket, listenerConfig) {
  if (listenerConfig.protocol !== 'smtp' || !listenerConfig.secureContext) {
    new SubmissionSession(socket, listenerConfig);
    return;
  }
  let settled = false;
  const timer = setTimeout(() => startPlainSession(), implicitTlsDetectTimeoutMs);

  function cleanup() {
    clearTimeout(timer);
    socket.off('data', onData);
    socket.off('error', onError);
  }

  function onError() {
    cleanup();
  }

  function onData(chunk) {
    socket.pause();
    if (isTlsClientHello(chunk)) {
      startImplicitTlsSession(chunk);
    } else {
      startPlainSession(chunk);
    }
  }

  function startPlainSession(firstChunk) {
    if (settled) return;
    settled = true;
    cleanup();
    const session = new SubmissionSession(socket, listenerConfig);
    if (firstChunk?.length) session.onData(firstChunk);
    socket.resume();
  }

  function startImplicitTlsSession(firstChunk) {
    if (settled) return;
    settled = true;
    cleanup();
    socket.unshift(firstChunk);
    const secureSocket = new tls.TLSSocket(socket, {
      isServer: true,
      secureContext: listenerConfig.secureContext
    });
    const secureConfig = {
      ...listenerConfig,
      tlsActive: true,
      startTlsAvailable: false
    };
    let sessionStarted = false;
    const startSession = () => {
      if (sessionStarted) return;
      sessionStarted = true;
      secureSocket.off('secure', startSession);
      secureSocket.off('secureConnect', startSession);
      new SubmissionSession(secureSocket, secureConfig);
      secureSocket.resume();
    };
    secureSocket.once('secure', startSession);
    secureSocket.once('secureConnect', startSession);
    secureSocket.on('error', () => null);
    secureSocket.resume();
  }

  socket.once('data', onData);
  socket.once('error', onError);
}

function isTlsClientHello(chunk) {
  return chunk?.length >= 3 && chunk[0] === 0x16 && chunk[1] === 0x03;
}

export function parseSubmissionListeners(value) {
  return String(value || '25:smtp,587:smtp,465:smtps,2525:smtp')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean)
    .map((item) => {
      const [portRaw, protocolRaw = 'smtp'] = item.split(':');
      const port = Number(portRaw);
      const protocol = protocolRaw.toLowerCase() === 'smtps' ? 'smtps' : 'smtp';
      if (!Number.isInteger(port) || port <= 0 || port > 65535) return null;
      return { port, protocol };
    })
    .filter(Boolean);
}

export function publicSubmissionListeners(listeners) {
  return listeners.map((listener) => ({
    port: listener.port,
    protocol: listener.protocol === 'smtps' ? 'SMTPS' : 'SMTP + STARTTLS'
  }));
}

class SubmissionSession {
  constructor(socket, config) {
    this.socket = socket;
    this.config = config;
    this.buffer = '';
    this.dataMode = false;
    this.dataLines = [];
    this.authState = '';
    this.authUser = '';
    this.user = null;
    this.authenticated = false;
    this.mailFrom = '';
    this.mailFromAccepted = false;
    this.recipients = [];
    this.inboundMailboxes = [];
    this.inboundRoutes = [];
    this.dataBytes = 0;
    this.dataTooLarge = false;
    this.remoteAddress = socket.remoteAddress || '';
    this.onDataBound = (chunk) => this.onData(chunk);
    this.queue = Promise.resolve();
    socket.setEncoding('utf8');
    socket.on('data', this.onDataBound);
    socket.on('error', () => null);
    this.write(220, `${config.hostname} MailHub SMTP ready`);
  }

  onData(chunk) {
    this.buffer += chunk;
    let index;
    while ((index = this.buffer.indexOf('\n')) !== -1) {
      const line = this.buffer.slice(0, index).replace(/\r$/, '');
      this.buffer = this.buffer.slice(index + 1);
      this.queue = this.queue
        .then(() => this.onLine(line))
        .catch((error) => {
          console.error(error);
          this.write(451, 'Temporary local error');
        });
    }
  }

  async onLine(line) {
    if (this.dataMode) {
      if (line === '.') return await this.finishData();
      const dataLine = line.startsWith('..') ? line.slice(1) : line;
      const nextBytes = this.dataBytes + Buffer.byteLength(`${dataLine}\r\n`, 'utf8');
      if (nextBytes > this.maxMessageBytes()) {
        this.dataTooLarge = true;
        this.dataBytes = nextBytes;
        return;
      }
      if (!this.dataTooLarge) {
        this.dataLines.push(dataLine);
        this.dataBytes = nextBytes;
      }
      return;
    }

    if (this.authState) return this.continueAuth(line);

    const [rawCommand, ...args] = line.split(' ');
    const command = rawCommand.toUpperCase();
    const argument = args.join(' ').trim();

    if (command === 'EHLO' || command === 'HELO') return this.ehlo();
    if (command === 'NOOP') return this.write(250, 'OK');
    if (command === 'RSET') return this.resetEnvelope();
    if (command === 'QUIT') {
      this.write(221, 'Bye');
      return this.socket.end();
    }
    if (command === 'AUTH') return this.auth(argument);
    if (command === 'STARTTLS') return this.startTls();
    if (command === 'MAIL') return this.mail(argument);
    if (command === 'RCPT') return this.rcpt(argument);
    if (command === 'DATA') return this.data();
    return this.write(502, 'Command not implemented');
  }

  ehlo() {
    this.socket.write(`250-${this.config.hostname}\r\n`);
    this.socket.write(`250-SIZE ${this.maxMessageBytes()}\r\n`);
    this.socket.write('250-8BITMIME\r\n');
    if (this.config.startTlsAvailable && !this.config.tlsActive) {
      this.socket.write('250-STARTTLS\r\n');
    }
    if (this.canAuthenticate()) {
      this.socket.write('250-AUTH PLAIN LOGIN\r\n');
    }
    this.socket.write('250 SMTPUTF8\r\n');
  }

  startTls() {
    if (!this.config.startTlsAvailable || !this.config.secureContext) return this.write(454, 'TLS is not available');
    if (this.config.tlsActive) return this.write(503, 'TLS is already active');
    this.write(220, 'Ready to start TLS');
    this.socket.removeListener('data', this.onDataBound);
    const secureSocket = new tls.TLSSocket(this.socket, {
      isServer: true,
      secureContext: this.config.secureContext
    });
    this.socket = secureSocket;
    this.buffer = '';
    this.authenticated = false;
    this.user = null;
    this.authState = '';
    this.config = {
      ...this.config,
      tlsActive: true,
      startTlsAvailable: false
    };
    secureSocket.setEncoding('utf8');
    secureSocket.on('data', this.onDataBound);
    secureSocket.on('error', () => null);
  }

  auth(argument) {
    if (!this.canAuthenticate()) return this.write(538, 'Encryption required for authentication');
    const [methodRaw, response] = argument.split(/\s+/, 2);
    const method = String(methodRaw || '').toUpperCase();
    if (method === 'PLAIN') {
      if (!response) {
        this.authState = 'plain';
        return this.write(334, '');
      }
      return this.finishPlainAuth(response);
    }
    if (method === 'LOGIN') {
      this.authState = 'login-username';
      return this.write(334, Buffer.from('Username:').toString('base64'));
    }
    return this.write(504, 'Unsupported authentication method');
  }

  continueAuth(line) {
    if (this.authState === 'plain') return this.finishPlainAuth(line);
    if (this.authState === 'login-username') {
      this.authUser = decodeBase64(line);
      this.authState = 'login-password';
      return this.write(334, Buffer.from('Password:').toString('base64'));
    }
    if (this.authState === 'login-password') {
      const password = decodeBase64(line);
      this.authState = '';
      return this.finishAuth(this.authUser, password);
    }
  }

  finishPlainAuth(response) {
    const decoded = decodeBase64(response);
    const parts = decoded.split('\u0000');
    const user = parts[1] || parts[0] || '';
    const password = parts[2] || parts[1] || '';
    this.authState = '';
    return this.finishAuth(user, password);
  }

  finishAuth(user, password) {
    const auth = verifySmtpCredential(user, password);
    if (auth?.user) {
      this.user = auth.user;
      this.authenticated = true;
      return this.write(235, 'Authentication successful');
    }
    this.user = null;
    this.authenticated = false;
    return this.write(535, 'Authentication failed');
  }

  mail(argument) {
    if (!this.authenticated && !this.config.inboundEnabled) return this.write(530, 'Authentication required');
    const address = extractPathAddress(argument, { allowEmpty: !this.authenticated });
    if (address === null) return this.write(501, 'Invalid MAIL FROM');
    this.mailFrom = address;
    this.mailFromAccepted = true;
    this.recipients = [];
    this.inboundMailboxes = [];
    this.inboundRoutes = [];
    return this.write(250, 'Sender OK');
  }

  rcpt(argument) {
    if (!this.authenticated && !this.config.inboundEnabled) return this.write(530, 'Authentication required');
    if (!this.mailFromAccepted) return this.write(503, 'MAIL FROM required first');
    const address = extractPathAddress(argument);
    if (address === null || !address) return this.write(501, 'Invalid RCPT TO');
    if (this.recipients.length >= 100) return this.write(452, 'Too many recipients');
    if (!this.authenticated) {
      const route = resolveInboundRecipient(address);
      if (!route) return this.write(550, 'Recipient is not a local MailHub mailbox');
      if (route.mailbox) this.inboundMailboxes.push(route.mailbox);
      this.inboundRoutes.push(route);
      this.recipients.push(address);
      return this.write(250, 'Recipient OK');
    }
    this.recipients.push(address);
    return this.write(250, 'Recipient OK');
  }

  data() {
    if (!this.authenticated && !this.config.inboundEnabled) return this.write(530, 'Authentication required');
    if (!this.mailFromAccepted || !this.recipients.length) return this.write(503, 'Need MAIL FROM and RCPT TO first');
    this.dataMode = true;
    this.dataLines = [];
    this.dataBytes = 0;
    this.dataTooLarge = false;
    return this.write(354, 'End data with <CR><LF>.<CR><LF>');
  }

  async finishData() {
    this.dataMode = false;
    if (this.dataTooLarge) {
      this.resetEnvelope(false);
      return this.write(552, 'Message size exceeds fixed maximum message size');
    }
    const rawMessage = `${this.dataLines.join('\r\n')}\r\n`;
    if (!this.authenticated) return await this.finishInboundData(rawMessage);
    const headerFrom = extractHeader(rawMessage, 'from');
    const subject = decodeHeader(extractHeader(rawMessage, 'subject')) || '(no subject)';
    const sender = extractAddress(headerFrom) || this.mailFrom;
    const domainName = domainFromAddress(sender || this.mailFrom);
    const domain = getDomainByName(domainName, { userId: this.user?.id, includePrivate: true });
    if (!domain) {
      logSendEvent({
        userId: this.user?.id || null,
        domainId: null,
        sender: sender || this.mailFrom,
        recipients: this.recipients,
        subject,
        status: 'failed',
        detail: `Sender domain ${domainName || '(unknown)'} is not configured`
      });
      return this.write(550, 'Sender domain is not configured in MailHub');
    }

    const trackingSettings = this.config.getTrackingSettings?.() || {};
    const requestedTracking = resolveSubmissionTracking(rawMessage, trackingSettings.enabled);
    const trackingAvailable = Boolean(trackingSettings.appBaseUrl && trackingSettings.secret);
    const requestedOpens = requestedTracking.opens && trackingAvailable;
    const requestedClicks = requestedTracking.clicks && trackingAvailable;
    const openToken = requestedOpens ? createTrackingToken() : '';
    const eventId = createSendEvent({
      userId: this.user.id,
      domainId: domain.id,
      sender: sender || this.mailFrom,
      recipients: this.recipients,
      subject,
      trackingToken: openToken,
      trackingOpens: requestedOpens,
      trackingClicks: requestedClicks
    });

    try {
      let preparedMessage = rawMessage;
      let trackingOpens = false;
      let trackingClicks = false;
      if (requestedOpens || requestedClicks) {
        const result = await instrumentRawMime(preparedMessage, {
          openPixelUrl: requestedOpens
            ? `${trackingUrlBase(trackingSettings.appBaseUrl)}/t/o/${openToken}.gif`
            : '',
          createClickUrl: requestedClicks
            ? (target) => createSubmissionClickUrl({
                appBaseUrl: trackingSettings.appBaseUrl,
                secret: trackingSettings.secret,
                userId: this.user.id,
                eventId,
                target
              })
            : null
        });
        preparedMessage = result.rawMessage;
        trackingOpens = requestedOpens && result.pixelAdded;
        trackingClicks = requestedClicks && result.linkCount > 0;
      }
      preparedMessage = await stripRawMimeHeaders(preparedMessage, ['x-mailhub-track']);
      const deliverabilitySettings = this.config.getDeliverabilitySettings?.() || {};
      preparedMessage = addHeadersToRawMessage(preparedMessage, buildDeliverabilityHeaders({
        from: sender || this.mailFrom,
        listUnsubscribeMailto: deliverabilitySettings.listUnsubscribeMailto,
        listUnsubscribeUrl: deliverabilitySettings.listUnsubscribeUrl,
        listUnsubscribePostEnabled: deliverabilitySettings.listUnsubscribePostEnabled,
        feedbackId: deliverabilitySettings.feedbackIdEnabled
          ? createFeedbackId({
              userId: this.user.id,
              domainId: domain.id,
              eventId,
              secret: deliverabilitySettings.secret
            })
          : '',
        reportAbuseTo: deliverabilitySettings.reportAbuseTo,
        csaComplaintsTo: deliverabilitySettings.csaComplaintsTo,
        context: {
          eventId,
          userId: this.user.id,
          domain: domainName,
          sender: sender || this.mailFrom,
          recipient: this.recipients.length === 1 ? this.recipients[0] : ''
        }
      }));
      const signed = signMessageForDomain(preparedMessage, domain);
      const smtpResult = await sendViaSmtp({
        host: this.config.relayHost,
        port: this.config.relayPort,
        secure: this.config.relaySecure,
        username: this.config.relayUsername,
        password: this.config.relayPassword,
        helo: this.config.relayHelo,
        mailFrom: resolveEnvelopeSender(deliverabilitySettings, this.mailFrom),
        recipients: this.recipients,
        rawMessage: signed
      });
      finalizeSendEvent(eventId, this.user.id, {
        status: 'queued',
        detail: `submission ${this.remoteAddress}; ${smtpResult.message}`,
        queueId: smtpResult.queueId,
        deliveryLog: smtpResult.deliveryLog,
        trackingOpens,
        trackingClicks
      });
      this.resetEnvelope(false);
      return this.write(250, 'Message queued');
    } catch (error) {
      finalizeSendEvent(eventId, this.user.id, {
        status: 'failed',
        detail: `submission ${this.remoteAddress}; ${error.message}`,
        deliveryLog: deliveryLogFromError(error)
      });
      return this.write(451, 'Temporary local delivery error');
    }
  }

  async finishInboundData(rawMessage) {
    if (!this.config.inboundEnabled) return this.write(530, 'Authentication required');
    if (!this.inboundRoutes.length) return this.write(550, 'Recipient is not a local MailHub mailbox');
    try {
      const parsedMessage = await parseInboundMessage(rawMessage, this.recipients);
      let storedCount = 0;
      let forwardedCount = 0;
      const forwardErrors = [];

      for (const route of this.inboundRoutes) {
        if (route.drop) continue;
        const forwardTo = route.forwardTo || [];
        const shouldStore = route.mailbox && (route.keepForwarded || !forwardTo.length);
        if (shouldStore) {
          const inboundMessage = createInboundMessage(route.mailbox, {
            ...parsedMessage,
            recipients: [route.recipient],
            sender: parsedMessage.sender || this.mailFrom
          });
          try {
            enqueueInboundWebhookDeliveries(inboundMessage);
          } catch (error) {
            // The message is already durable; webhook retries must not turn receipt into an SMTP failure.
            console.error(`Inbound webhook enqueue failed for ${route.recipient}: ${error.message}`);
          }
          storedCount += 1;
        }
        if (forwardTo.length) {
          try {
            await this.forwardInboundMessage(rawMessage, parsedMessage, route, forwardTo);
            forwardedCount += forwardTo.length;
          } catch (error) {
            forwardErrors.push({ route, error });
            console.warn(`Inbound forward failed for ${route.recipient}: ${error.message}`);
          }
        }
      }

      const hasForwardOnlyFailure = forwardErrors.some(({ route }) => !route.mailbox || !route.keepForwarded);
      if (hasForwardOnlyFailure || (!storedCount && !forwardedCount && forwardErrors.length)) {
        return this.write(451, 'Temporary local delivery error');
      }
      this.resetEnvelope(false);
      return this.write(250, 'Message accepted');
    } catch (error) {
      console.error(error);
      return this.write(451, 'Temporary local delivery error');
    }
  }

  async forwardInboundMessage(rawMessage, parsedMessage, route, recipients) {
    const sender = extractAddress(this.mailFrom) ||
      extractAddress(parsedMessage.sender) ||
      route.mailbox?.address ||
      `postmaster@${route.mailbox?.domain || this.config.hostname}`;
    await sendViaSmtp({
      host: this.config.relayHost,
      port: this.config.relayPort,
      secure: this.config.relaySecure,
      username: this.config.relayUsername,
      password: this.config.relayPassword,
      helo: this.config.relayHelo,
      mailFrom: sender,
      recipients,
      rawMessage
    });
  }

  resetEnvelope(reply = true) {
    this.mailFrom = '';
    this.mailFromAccepted = false;
    this.recipients = [];
    this.inboundMailboxes = [];
    this.inboundRoutes = [];
    this.dataMode = false;
    this.dataLines = [];
    this.dataBytes = 0;
    this.dataTooLarge = false;
    this.user = this.authenticated ? this.user : null;
    if (reply) this.write(250, 'OK');
  }

  write(code, message) {
    this.socket.write(`${code} ${message}\r\n`);
  }

  canAuthenticate() {
    return this.config.tlsActive || this.config.allowInsecureAuth;
  }

  maxMessageBytes() {
    const value = Number(this.config.maxMessageBytes || defaultMaxMessageBytes);
    return Number.isFinite(value) && value > 0 ? Math.floor(value) : defaultMaxMessageBytes;
  }
}

function extractPathAddress(argument, { allowEmpty = false } = {}) {
  const match = String(argument || '').match(/FROM:\s*<([^>]*)>|TO:\s*<([^>]*)>/i);
  const raw = match ? (match[1] ?? match[2]) : argument;
  if (allowEmpty && String(raw || '').trim() === '') return '';
  return extractAddress(raw) || null;
}

function extractHeader(rawMessage, name) {
  const head = rawMessage.split(/\r?\n\r?\n/, 1)[0] || '';
  const lines = head.split(/\r?\n/);
  const headers = [];
  for (const line of lines) {
    if (/^[\t ]/.test(line) && headers.length) {
      headers[headers.length - 1].value += ` ${line.trim()}`;
      continue;
    }
    const index = line.indexOf(':');
    if (index === -1) continue;
    headers.push({
      name: line.slice(0, index).toLowerCase(),
      value: line.slice(index + 1).trim()
    });
  }
  return headers.reverse().find((header) => header.name === name.toLowerCase())?.value || '';
}

function decodeHeader(value) {
  return String(value || '').replace(/=\?UTF-8\?B\?([^?]+)\?=/gi, (_, encoded) => {
    try {
      return Buffer.from(encoded, 'base64').toString('utf8');
    } catch {
      return _;
    }
  });
}

function decodeBase64(value) {
  try {
    return Buffer.from(String(value || ''), 'base64').toString('utf8');
  } catch {
    return '';
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
