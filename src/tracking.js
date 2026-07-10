import crypto from 'node:crypto';
import { Readable, Transform } from 'node:stream';
import { Joiner, Rewriter, Splitter } from '@zone-eu/mailsplit';
import { parse, parseFragment, serialize } from 'parse5';

const trackingTargetContext = 'mailhub-tracking-target:v1';

export function createTrackingToken() {
  return crypto.randomBytes(32).toString('base64url');
}

export function hashTrackingToken(token) {
  return crypto.createHash('sha256').update(String(token || '')).digest('hex');
}

export function normalizeTrackingTarget(value) {
  let url;
  try {
    url = new URL(String(value || ''));
  } catch {
    throw new Error('Tracking target must be an absolute HTTP URL.');
  }
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new Error('Tracking target must use HTTP or HTTPS.');
  }
  if (!url.hostname) throw new Error('Tracking target must be an absolute HTTP URL.');
  return url.toString();
}

export function encryptTrackingTarget(value, secret) {
  const target = normalizeTrackingTarget(value);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', trackingEncryptionKey(secret), iv);
  cipher.setAAD(Buffer.from(trackingTargetContext));
  const ciphertext = Buffer.concat([cipher.update(target, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return ['v1', iv.toString('base64url'), ciphertext.toString('base64url'), tag.toString('base64url')].join('.');
}

export function decryptTrackingTarget(value, secret) {
  const [version, ivPart, ciphertextPart, tagPart, extra] = String(value || '').split('.');
  if (version !== 'v1' || !ivPart || !ciphertextPart || !tagPart || extra) {
    throw new Error('Invalid encrypted tracking target.');
  }
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    trackingEncryptionKey(secret),
    decodeCanonicalBase64Url(ivPart)
  );
  decipher.setAAD(Buffer.from(trackingTargetContext));
  decipher.setAuthTag(decodeCanonicalBase64Url(tagPart));
  const plaintext = Buffer.concat([
    decipher.update(decodeCanonicalBase64Url(ciphertextPart)),
    decipher.final()
  ]).toString('utf8');
  return normalizeTrackingTarget(plaintext);
}

export function trackingTargetFingerprint(value, secret) {
  return hmac(secret, `target:${normalizeTrackingTarget(value)}`);
}

export function hashTrackingClientIp({ ip, secret, userId, sendEventId, occurredAt }) {
  const day = new Date(occurredAt).toISOString().slice(0, 10);
  return hmac(secret, ['ip', userId, sendEventId, day, normalizeIp(ip)].join(':'));
}

export function classifyTrackingSource(userAgent) {
  const value = String(userAgent || '').toLowerCase();
  if (/googleimageproxy|ggpht\.com|yahoo.*proxy|outlook.*proxy|microsoft office.*image/.test(value)) return 'proxy';
  if (/scanner|barracuda|proofpoint|mimecast|safelinks|urlscan|spider|crawler|\bbot\b|curl\/|wget\//.test(value)) {
    return 'scanner';
  }
  return 'direct';
}

export function trackingReplayKey({
  secret,
  sendEventId,
  eventType,
  trackingLinkId = '',
  ipHash,
  userAgent,
  occurredAt
}) {
  const minute = Math.floor(new Date(occurredAt).getTime() / 60_000);
  const userAgentHash = crypto.createHash('sha256').update(String(userAgent || '')).digest('hex');
  return hmac(secret, ['replay', sendEventId, eventType, trackingLinkId, ipHash, userAgentHash, minute].join(':'));
}

export function instrumentHtml(html, { openPixelUrl = '', createClickUrl } = {}) {
  const source = String(html || '');
  const documentMode = /<!doctype\s|<html\b|<body\b/i.test(source);
  const root = documentMode ? parse(source) : parseFragment(source);
  const trackingOrigin = safeOrigin(openPixelUrl);
  let linkCount = 0;
  let hasOpenPixel = false;
  let body = null;

  walkHtml(root, (node) => {
    if (node.tagName === 'body') body = node;
    if (hasAttribute(node, 'data-mailhub-open')) hasOpenPixel = true;
    if (node.tagName !== 'a' || hasAttribute(node, 'data-mailhub-no-track')) return;
    const href = getAttribute(node, 'href');
    if (!href || typeof createClickUrl !== 'function') return;
    let target;
    try {
      target = normalizeTrackingTarget(href);
    } catch {
      return;
    }
    const targetUrl = new URL(target);
    if (trackingOrigin && targetUrl.origin === trackingOrigin && targetUrl.pathname.startsWith('/t/c/')) return;
    const clickUrl = createClickUrl(target);
    if (!clickUrl) return;
    setAttribute(node, 'href', String(clickUrl));
    linkCount += 1;
  });

  let pixelAdded = false;
  if (openPixelUrl && !hasOpenPixel) {
    const pixel = parseFragment(
      `<img data-mailhub-open="true" src="${escapeHtmlAttribute(openPixelUrl)}" alt="" width="1" height="1" border="0" style="display:none!important;width:1px!important;height:1px!important" referrerpolicy="no-referrer">`
    ).childNodes[0];
    const parent = body || root;
    pixel.parentNode = parent;
    parent.childNodes = [...(parent.childNodes || []), pixel];
    pixelAdded = true;
  }

  return {
    html: serialize(root),
    linkCount,
    pixelAdded
  };
}

export async function instrumentRawMime(rawMessage, options = {}) {
  const source = String(rawMessage || '');
  const skipReason = rawMimeSkipReason(source);
  if (skipReason) return unchangedMimeResult(source, skipReason);

  let linkCount = 0;
  let pixelAdded = false;
  let htmlParts = 0;
  let protectedHtmlParts = 0;
  let unsupportedHtmlParts = 0;
  const splitter = new Splitter({ ignoreEmbedded: true });
  const rewriter = new Rewriter((node) => {
    if (node.contentType !== 'text/html' || node.disposition === 'attachment') return false;
    if (hasProtectedMimeAncestor(node)) {
      protectedHtmlParts += 1;
      return false;
    }
    if (!supportsMimeCharset(node.charset)) {
      unsupportedHtmlParts += 1;
      return false;
    }
    return true;
  });
  const joiner = new Joiner();

  rewriter.on('node', (data) => {
    htmlParts += 1;
    const chunks = [];
    data.decoder.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
    data.decoder.on('error', (error) => data.encoder.destroy(error));
    data.decoder.on('end', () => {
      const body = Buffer.concat(chunks);
      try {
        const result = instrumentHtml(decodeMimeText(body, data.node.charset), {
          ...options,
          openPixelUrl: pixelAdded ? '' : options.openPixelUrl
        });
        linkCount += result.linkCount;
        pixelAdded ||= result.pixelAdded;
        data.node.setCharset('utf-8');
        data.encoder.end(Buffer.from(result.html, 'utf8'));
      } catch (error) {
        unsupportedHtmlParts += 1;
        data.encoder.end(body);
      }
    });
  });

  const output = [];
  await new Promise((resolve, reject) => {
    joiner.on('data', (chunk) => output.push(Buffer.from(chunk)));
    joiner.on('end', resolve);
    joiner.on('error', reject);
    splitter.on('error', reject);
    rewriter.on('error', reject);
    Readable.from([Buffer.from(source)]).pipe(splitter).pipe(rewriter).pipe(joiner);
  });

  return {
    rawMessage: Buffer.concat(output).toString('utf8'),
    tracked: htmlParts > 0 && (linkCount > 0 || pixelAdded),
    skippedReason: trackingMimeSkipReason({ htmlParts, protectedHtmlParts, unsupportedHtmlParts }),
    linkCount,
    pixelAdded
  };
}

export async function stripRawMimeHeaders(rawMessage, headerNames = []) {
  const source = String(rawMessage || '');
  if (rawMimeSkipReason(source)) return source;
  const names = new Set((headerNames || []).map((name) => String(name).toLowerCase()));
  if (!names.size) return source;
  const splitter = new Splitter({ ignoreEmbedded: true });
  const headerStripper = new Transform({
    objectMode: true,
    transform(data, _encoding, callback) {
      if (data.type === 'node' && data.root) {
        for (const name of names) data.headers.remove(name);
      }
      callback(null, data);
    }
  });
  const joiner = new Joiner();
  const output = [];
  await new Promise((resolve, reject) => {
    joiner.on('data', (chunk) => output.push(Buffer.from(chunk)));
    joiner.on('end', resolve);
    joiner.on('error', reject);
    splitter.on('error', reject);
    headerStripper.on('error', reject);
    Readable.from([Buffer.from(source)]).pipe(splitter).pipe(headerStripper).pipe(joiner);
  });
  return Buffer.concat(output).toString('utf8');
}

function trackingEncryptionKey(secret) {
  const value = String(secret || '');
  if (!value) throw new Error('TRACKING_SECRET is required.');
  return crypto.createHash('sha256').update(`${trackingTargetContext}:${value}`).digest();
}

function hmac(secret, value) {
  const key = String(secret || '');
  if (!key) throw new Error('TRACKING_SECRET is required.');
  return crypto.createHmac('sha256', key).update(value).digest('hex');
}

function normalizeIp(value) {
  return String(value || '').trim().toLowerCase() || 'unknown';
}

function decodeCanonicalBase64Url(value) {
  const buffer = Buffer.from(String(value || ''), 'base64url');
  if (!buffer.length || buffer.toString('base64url') !== value) {
    throw new Error('Invalid encrypted tracking target.');
  }
  return buffer;
}

function walkHtml(node, visit) {
  visit(node);
  for (const child of node.childNodes || []) walkHtml(child, visit);
}

function hasAttribute(node, name) {
  return Boolean(node?.attrs?.some((attribute) => attribute.name === name));
}

function getAttribute(node, name) {
  return node?.attrs?.find((attribute) => attribute.name === name)?.value || '';
}

function setAttribute(node, name, value) {
  const existing = node.attrs?.find((attribute) => attribute.name === name);
  if (existing) existing.value = value;
  else node.attrs = [...(node.attrs || []), { name, value }];
}

function safeOrigin(value) {
  try {
    return new URL(String(value || '')).origin;
  } catch {
    return '';
  }
}

function escapeHtmlAttribute(value) {
  return String(value || '')
    .replaceAll('&', '&amp;')
    .replaceAll('"', '&quot;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');
}

function rawMimeSkipReason(rawMessage) {
  const headerBlock = String(rawMessage || '').split(/\r?\n\r?\n/, 1)[0];
  if (/^DKIM-Signature:/im.test(headerBlock)) return 'existing-dkim';
  const unfolded = headerBlock.replace(/\r?\n[\t ]+/g, ' ');
  if (/^Content-Type:\s*multipart\/signed\b/im.test(unfolded)) return 'signed';
  if (/^Content-Type:\s*(?:multipart\/encrypted|application\/(?:pkcs7-mime|x-pkcs7-mime|pgp-encrypted))\b/im.test(unfolded)) {
    return 'encrypted';
  }
  return '';
}

function hasProtectedMimeAncestor(node) {
  for (let current = node; current; current = current.parentNode) {
    if (current.contentType === 'multipart/signed') return true;
    if (current.contentType === 'multipart/encrypted') return true;
    if (['application/pkcs7-mime', 'application/x-pkcs7-mime', 'application/pgp-encrypted'].includes(current.contentType)) {
      return true;
    }
  }
  return false;
}

function supportsMimeCharset(charset) {
  try {
    new TextDecoder(String(charset || 'utf-8'), { fatal: true });
    return true;
  } catch {
    return false;
  }
}

function decodeMimeText(value, charset) {
  return new TextDecoder(String(charset || 'utf-8'), { fatal: true }).decode(value);
}

function trackingMimeSkipReason({ htmlParts, protectedHtmlParts, unsupportedHtmlParts }) {
  if (htmlParts > 0) return '';
  if (protectedHtmlParts > 0) return 'protected-mime';
  if (unsupportedHtmlParts > 0) return 'unsupported-charset';
  return 'no-html';
}

function unchangedMimeResult(rawMessage, skippedReason) {
  return {
    rawMessage,
    tracked: false,
    skippedReason,
    linkCount: 0,
    pixelAdded: false
  };
}
