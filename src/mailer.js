import net from 'node:net';
import tls from 'node:tls';
import crypto from 'node:crypto';
import { extractQueueIdFromSmtpResponse } from './delivery-tracker.js';
import { signDkim } from './dkim.js';

export function parseAddressList(value) {
  return String(value || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean)
    .map(extractAddress)
    .filter(Boolean);
}

export function extractAddress(value) {
  const match = String(value || '').match(/<([^<>@\s]+@[^<>@\s]+)>/);
  const address = match ? match[1] : String(value || '').trim();
  if (!/^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+$/.test(address)) return '';
  return address.toLowerCase();
}

export function domainFromAddress(value) {
  const address = extractAddress(value);
  return address.split('@')[1] || '';
}

export function buildMessage({ from, to, subject, text, html, baseUrl, headers: extraHeaders = [] }) {
  const recipients = Array.isArray(to) ? to : parseAddressList(to);
  if (!recipients.length) throw new Error('At least one recipient is required.');
  const messageIdHost = domainFromAddress(from) || 'localhost';
  const messageId = `<${crypto.randomUUID()}@${messageIdHost}>`;
  const commonHeaders = [
    ['From', sanitizeHeader(from)],
    ['To', recipients.join(', ')],
    ['Subject', encodeHeader(subject || '(no subject)')],
    ['Date', new Date().toUTCString()],
    ['Message-ID', messageId],
    ['MIME-Version', '1.0'],
    ...normalizeExtraHeaders(extraHeaders),
    ['X-MailHub', baseUrl || 'mailhub']
  ];

  if (html) {
    const boundary = `mailhub-${crypto.randomBytes(12).toString('hex')}`;
    const headers = [
      ...commonHeaders,
      ['Content-Type', `multipart/alternative; boundary="${boundary}"`]
    ];
    const body = [
      `--${boundary}`,
      'Content-Type: text/plain; charset=UTF-8',
      'Content-Transfer-Encoding: base64',
      '',
      encodeBase64Body(text || stripHtml(html)),
      `--${boundary}`,
      'Content-Type: text/html; charset=UTF-8',
      'Content-Transfer-Encoding: base64',
      '',
      encodeBase64Body(html),
      `--${boundary}--`,
      ''
    ].join('\r\n');
    return `${formatHeaders(headers)}\r\n\r\n${body}`;
  }

  const headers = [
    ...commonHeaders,
    ['Content-Type', 'text/plain; charset=UTF-8'],
    ['Content-Transfer-Encoding', 'base64']
  ];
  return `${formatHeaders(headers)}\r\n\r\n${encodeBase64Body(text || '')}\r\n`;
}

export function signMessageForDomain(rawMessage, domain) {
  if (!domain?.dkimPrivate || !domain?.selector) return rawMessage;
  return signDkim(rawMessage, {
    domain: domain.domain,
    selector: domain.selector,
    privateKey: domain.dkimPrivate,
    identity: `@${domain.domain}`
  });
}

export function buildDeliverabilityHeaders({
  from = '',
  listUnsubscribeMailto = '',
  listUnsubscribeUrl = '',
  listUnsubscribePostEnabled = false,
  feedbackId = '',
  reportAbuseTo = '',
  csaComplaintsTo = '',
  context = {}
} = {}) {
  const headers = [];
  const unsubscribeLinks = [];
  const mailto = normalizeMailtoListUnsubscribe(listUnsubscribeMailto);
  const url = normalizeHttpListUnsubscribe(renderDeliverabilityTemplate(listUnsubscribeUrl, context));
  if (mailto) unsubscribeLinks.push(`<${mailto}>`);
  if (url) unsubscribeLinks.push(`<${url}>`);
  if (unsubscribeLinks.length) {
    headers.push(['List-Unsubscribe', unsubscribeLinks.join(', ')]);
    if (listUnsubscribePostEnabled && isHttpsUrl(url)) {
      headers.push(['List-Unsubscribe-Post', 'List-Unsubscribe=One-Click']);
    }
  }

  const normalizedFeedbackId = normalizeFeedbackId(feedbackId);
  if (normalizedFeedbackId) headers.push(['Feedback-Id', normalizedFeedbackId]);

  const abuse = sanitizeHeader(reportAbuseTo);
  if (abuse) headers.push(['X-Report-Abuse-To', abuse]);

  const complaints = sanitizeHeader(csaComplaintsTo);
  if (complaints) headers.push(['X-CSA-Complaints', complaints]);

  const sender = extractAddress(from);
  if (sender) headers.push(['X-Sender', sender]);

  return headers;
}

export function addHeadersToRawMessage(rawMessage, headers = []) {
  const extraHeaders = normalizeExtraHeaders(headers);
  if (!extraHeaders.length) return rawMessage;
  const normalized = normalizeMimeMessage(rawMessage);
  const separator = normalized.indexOf('\r\n\r\n');
  if (separator === -1) return `${formatHeaders(extraHeaders)}\r\n\r\n${normalized}`;

  const headerBlock = normalized.slice(0, separator);
  const body = normalized.slice(separator + 4);
  const existingNames = new Set(parseHeaderNames(headerBlock));
  const missingHeaders = extraHeaders.filter(([name]) => !existingNames.has(name.toLowerCase()));
  if (!missingHeaders.length) return normalized;
  return `${headerBlock}\r\n${formatHeaders(missingHeaders)}\r\n\r\n${body}`;
}

export function createFeedbackId({ userId, domainId, eventId, secret, product = 'MailHub' } = {}) {
  const key = String(secret || 'mailhub-feedback');
  const safeProduct = normalizeFeedbackId(product) || 'MailHub';
  return [
    'mh',
    feedbackPart('user', userId, key),
    feedbackPart('domain', domainId, key),
    `${feedbackPart('event', eventId, key)}:${safeProduct}`
  ].join('.');
}

export function resolveEnvelopeSender(settings = {}, fallback = '') {
  if (!settings.bounceEnvelopeEnabled) return fallback;
  return extractAddress(settings.bounceAddress) || fallback;
}

export async function sendViaSmtp({ host, port, secure, username, password, helo, mailFrom, recipients, rawMessage }) {
  const deliveryLog = [];
  const addLog = (entry) => deliveryLog.push({ at: new Date().toISOString(), ...entry });
  if (!host) {
    const error = new Error('SMTP_HOST is not configured.');
    error.deliveryLog = deliveryLog;
    throw error;
  }
  let client;
  try {
    addLog({
      phase: 'connect',
      direction: 'system',
      message: `Connecting to ${host}:${Number(port || 25)}${secure ? ' with TLS' : ''}`
    });
    client = await SmtpClient.connect({ host, port, secure });
    addLog({
      phase: 'connect',
      direction: 'system',
      message: `Connected to ${host}:${Number(port || 25)}`,
      ok: true
    });
    await expectResponse(client, [220], 'connect', addLog);
    let response = await runCommand(client, `EHLO ${helo || 'mailhub.local'}`, [250, 502, 500], 'smtp', addLog);
    if (![250].includes(response.code)) {
      await runCommand(client, `HELO ${helo || 'mailhub.local'}`, [250], 'smtp', addLog);
    }
    if (username || password) {
      const auth = Buffer.from(`\u0000${username || ''}\u0000${password || ''}`).toString('base64');
      await runCommand(client, `AUTH PLAIN ${auth}`, [235], 'auth', addLog);
    }
    await runCommand(client, `MAIL FROM:<${extractAddress(mailFrom)}>`, [250], 'envelope', addLog);
    for (const recipient of recipients) {
      await runCommand(client, `RCPT TO:<${recipient}>`, [250, 251], 'envelope', addLog);
    }
    await runCommand(client, 'DATA', [354], 'data', addLog);
    addLog({
      phase: 'data',
      direction: 'client',
      message: 'Message content transmitted',
      messageBytes: Buffer.byteLength(rawMessage || '', 'utf8'),
      ok: true
    });
    await client.writeData(dotStuff(rawMessage));
    const dataResponse = await expectResponse(client, [250], 'queue', addLog);
    await runCommand(client, 'QUIT', [221], 'quit', addLog).catch((error) => {
      addLog({
        phase: 'quit',
        direction: 'system',
        message: error.message,
        ok: false
      });
    });
    return {
      ...dataResponse,
      queueId: extractQueueIdFromSmtpResponse(dataResponse.message),
      deliveryLog
    };
  } catch (error) {
    addLog({
      phase: 'error',
      direction: 'system',
      message: error.message,
      ok: false
    });
    error.deliveryLog = deliveryLog;
    throw error;
  } finally {
    client?.close();
  }
}

async function runCommand(client, command, expectedCodes, phase, addLog) {
  addLog({
    phase,
    direction: 'client',
    command: sanitizeSmtpCommand(command)
  });
  const response = await client.command(command, expectedCodes);
  addLog({
    phase,
    direction: 'server',
    code: response.code,
    response: response.message,
    ok: true
  });
  return response;
}

async function expectResponse(client, expectedCodes, phase, addLog) {
  const response = await client.expect(expectedCodes);
  addLog({
    phase,
    direction: 'server',
    code: response.code,
    response: response.message,
    ok: true
  });
  return response;
}

function sanitizeSmtpCommand(command) {
  return String(command || '').replace(/^AUTH\s+(\S+)(?:\s+.*)?$/i, 'AUTH $1 <redacted>');
}

function sanitizeHeader(value) {
  return String(value || '').replace(/[\r\n]+/g, ' ').trim();
}

function encodeHeader(value) {
  const clean = sanitizeHeader(value);
  if (/^[\x20-\x7e]*$/.test(clean)) return clean;
  return `=?UTF-8?B?${Buffer.from(clean).toString('base64')}?=`;
}

function formatHeaders(headers) {
  return headers
    .filter(([, value]) => value !== undefined && value !== null && value !== '')
    .map(([name, value]) => formatHeader(name, value))
    .join('\r\n');
}

function formatHeader(name, value) {
  const line = `${name}: ${value}`;
  if (line.length <= 78) return line;
  return foldStructuredHeader(name, value);
}

function foldStructuredHeader(name, value) {
  const prefix = `${name}: `;
  const lines = [];
  let current = prefix;
  for (const token of splitHeaderTokens(value)) {
    if (current.length > prefix.length && current.length + token.length > 78) {
      lines.push(current.trimEnd());
      current = ` ${token.trimStart()}`;
      continue;
    }
    current += token;
  }
  lines.push(current.trimEnd());
  return lines.join('\r\n');
}

function splitHeaderTokens(value) {
  return String(value).split(/((?:,\s+)|\s+)/).filter(Boolean);
}

function normalizeExtraHeaders(headers) {
  return (headers || [])
    .filter((header) => Array.isArray(header) && isHeaderName(header[0]))
    .map(([name, value]) => [String(name), sanitizeHeader(value)])
    .filter(([, value]) => value);
}

function isHeaderName(value) {
  return /^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$/.test(String(value || ''));
}

function normalizeMailtoListUnsubscribe(value) {
  const clean = sanitizeHeader(value);
  if (!clean) return '';
  if (/^mailto:/i.test(clean)) return clean;
  const address = extractAddress(clean);
  return address ? `mailto:${address}` : '';
}

function normalizeHttpListUnsubscribe(value) {
  const clean = sanitizeHeader(value);
  if (!clean) return '';
  try {
    const url = new URL(clean);
    if (!['http:', 'https:'].includes(url.protocol)) return '';
    return url.toString();
  } catch {
    return '';
  }
}

function isHttpsUrl(value) {
  try {
    return new URL(value).protocol === 'https:';
  } catch {
    return false;
  }
}

function normalizeMimeMessage(value) {
  return String(value || '').replace(/\r?\n/g, '\r\n');
}

function parseHeaderNames(headerBlock) {
  const names = [];
  for (const line of String(headerBlock || '').split('\r\n')) {
    if (/^[\t ]/.test(line)) continue;
    const index = line.indexOf(':');
    if (index === -1) continue;
    names.push(line.slice(0, index).toLowerCase());
  }
  return names;
}

function renderDeliverabilityTemplate(value, context = {}) {
  return String(value || '').replace(/\{(eventId|recipient|sender|domain|userId)\}/g, (_match, key) => {
    const replacement = context[key] ?? '';
    return encodeURIComponent(String(replacement));
  });
}

function normalizeFeedbackId(value) {
  const clean = sanitizeHeader(value);
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(clean)) return '';
  return clean;
}

function feedbackPart(name, value, secret) {
  return crypto
    .createHmac('sha256', secret)
    .update(`${name}:${String(value ?? '')}`)
    .digest('hex')
    .slice(0, 12);
}

function normalizeBody(value) {
  return String(value || '').replace(/\r?\n/g, '\r\n');
}

function encodeBase64Body(value) {
  const encoded = Buffer.from(normalizeBody(value), 'utf8').toString('base64');
  return encoded.replace(/.{1,76}/g, '$&\r\n').trimEnd();
}

function stripHtml(value) {
  return String(value || '')
    .replace(/<style[\s\S]*?<\/style>/gi, '')
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function dotStuff(rawMessage) {
  const normalized = rawMessage.replace(/\r?\n/g, '\r\n');
  return `${normalized.replace(/^\./gm, '..')}\r\n.`;
}

class SmtpClient {
  static connect({ host, port = 25, secure = false }) {
    return new Promise((resolve, reject) => {
      const socket = secure
        ? tls.connect({ host, port: Number(port), servername: host })
        : net.createConnection({ host, port: Number(port) });
      const client = new SmtpClient(socket);
      socket.once('connect', () => resolve(client));
      socket.once('secureConnect', () => resolve(client));
      socket.once('error', reject);
      setTimeout(() => reject(new Error('SMTP connection timeout.')), 15000).unref();
    });
  }

  constructor(socket) {
    this.socket = socket;
    this.buffer = '';
    this.pending = [];
    this.currentLines = [];
    socket.setEncoding('utf8');
    socket.on('data', (chunk) => this.onData(chunk));
    socket.on('error', (error) => this.rejectPending(error));
    socket.on('close', () => this.rejectPending(new Error('SMTP connection closed.')));
  }

  command(command, expectedCodes) {
    this.socket.write(`${command}\r\n`);
    return this.expect(expectedCodes);
  }

  writeData(data) {
    this.socket.write(`${data}\r\n`);
    return Promise.resolve();
  }

  expect(expectedCodes) {
    return new Promise((resolve, reject) => {
      this.pending.push({ expectedCodes, resolve, reject });
      this.flushResponses();
    });
  }

  close() {
    this.socket.destroy();
  }

  onData(chunk) {
    this.buffer += chunk;
    let index;
    while ((index = this.buffer.indexOf('\n')) !== -1) {
      const rawLine = this.buffer.slice(0, index).replace(/\r$/, '');
      this.buffer = this.buffer.slice(index + 1);
      this.currentLines.push(rawLine);
      if (/^\d{3} /.test(rawLine)) {
        this.flushResponses();
      }
    }
  }

  flushResponses() {
    while (this.pending.length && this.currentLines.length) {
      const lastLine = this.currentLines[this.currentLines.length - 1];
      if (!/^\d{3} /.test(lastLine)) return;
      const responseLines = this.currentLines.splice(0);
      const code = Number(lastLine.slice(0, 3));
      const response = {
        code,
        message: responseLines.join('\n')
      };
      const pending = this.pending.shift();
      if (pending.expectedCodes.includes(code)) {
        pending.resolve(response);
      } else {
        pending.reject(new Error(`Unexpected SMTP response ${response.message}`));
      }
    }
  }

  rejectPending(error) {
    while (this.pending.length) {
      this.pending.shift().reject(error);
    }
  }
}
