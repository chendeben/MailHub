import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import {
  claimWebhookDeliveries,
  completeWebhookDeliveryFailure,
  completeWebhookDeliverySuccess,
  reapExpiredWebhookProcessing
} from './db.js';
import { eventTypeForStatus, signWebhookBody } from './webhook-model.js';

const DEFAULT_INTERVAL_MS = 10_000;
const DEFAULT_BATCH_SIZE = 3;
const FETCH_TIMEOUT_MS = 10_000;
const MAX_RESPONSE_BODY_BYTES = 4096;
const USER_AGENT = 'MailHub-Webhook/1.0';

const blockedAddresses = new net.BlockList();
// IPv4 special-use / private / metadata-adjacent
blockedAddresses.addSubnet('0.0.0.0', 8, 'ipv4');
blockedAddresses.addSubnet('10.0.0.0', 8, 'ipv4');
blockedAddresses.addSubnet('100.64.0.0', 10, 'ipv4');
blockedAddresses.addSubnet('127.0.0.0', 8, 'ipv4');
blockedAddresses.addSubnet('169.254.0.0', 16, 'ipv4');
blockedAddresses.addSubnet('172.16.0.0', 12, 'ipv4');
blockedAddresses.addSubnet('192.0.0.0', 24, 'ipv4');
blockedAddresses.addSubnet('192.0.2.0', 24, 'ipv4');
blockedAddresses.addSubnet('192.168.0.0', 16, 'ipv4');
blockedAddresses.addSubnet('198.18.0.0', 15, 'ipv4');
blockedAddresses.addSubnet('198.51.100.0', 24, 'ipv4');
blockedAddresses.addSubnet('203.0.113.0', 24, 'ipv4');
blockedAddresses.addSubnet('224.0.0.0', 4, 'ipv4');
blockedAddresses.addSubnet('240.0.0.0', 4, 'ipv4');
// IPv6 special-use (IPv4-mapped ::ffff:* handled in isBlockedIpAddress, not here —
// BlockList treats IPv4 as matching ::ffff:0:0/96 and would false-positive public IPs)
blockedAddresses.addAddress('::', 'ipv6');
blockedAddresses.addAddress('::1', 'ipv6');
blockedAddresses.addSubnet('64:ff9b::', 96, 'ipv6');
blockedAddresses.addSubnet('100::', 64, 'ipv6');
blockedAddresses.addSubnet('2001:db8::', 32, 'ipv6');
blockedAddresses.addSubnet('fc00::', 7, 'ipv6');
blockedAddresses.addSubnet('fe80::', 10, 'ipv6');
blockedAddresses.addSubnet('ff00::', 8, 'ipv6');

let workerHandle = null;

export function isBlockedIpAddress(address) {
  const value = String(address || '').trim().toLowerCase();
  if (!value) return true;

  const mapped = value.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (mapped) return isBlockedIpAddress(mapped[1]);

  const mappedHex = value.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i);
  if (mappedHex) {
    const hi = Number.parseInt(mappedHex[1], 16);
    const lo = Number.parseInt(mappedHex[2], 16);
    const ipv4 = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
    return isBlockedIpAddress(ipv4);
  }

  if (net.isIPv4(value)) {
    return blockedAddresses.check(value, 'ipv4');
  }
  if (net.isIPv6(value)) {
    return blockedAddresses.check(value, 'ipv6');
  }
  return true;
}

export function isLoopbackHostname(hostname) {
  const host = String(hostname || '')
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, '');
  return host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '0:0:0:0:0:0:0:1';
}

export function isLoopbackIpAddress(address) {
  const value = String(address || '').trim().toLowerCase();
  if (net.isIPv4(value)) return value.startsWith('127.');
  if (net.isIPv6(value)) {
    return value === '::1' || value === '0:0:0:0:0:0:0:1';
  }
  return false;
}

/**
 * Validate webhook URL scheme and resolved addresses (fail closed).
 * Resolves DNS once and returns every allowed address so callers can pin the TCP connection
 * (avoids TOCTOU / DNS rebinding between validation and fetch).
 *
 * @returns {Promise<{ url: URL, addresses: string[], pinnedAddress: string }>}
 */
export async function resolveSafeWebhookTarget(
  rawUrl,
  {
    allowHttpLocal = String(process.env.WEBHOOK_ALLOW_HTTP_LOCAL || '') === '1',
    dnsLookup = defaultDnsLookup
  } = {}
) {
  let parsed;
  try {
    parsed = new URL(String(rawUrl || ''));
  } catch {
    throw new Error('Invalid webhook URL');
  }

  const protocol = parsed.protocol.toLowerCase();
  const loopbackHost = isLoopbackHostname(parsed.hostname);
  const allowLocalHttp = allowHttpLocal && protocol === 'http:' && loopbackHost;

  if (protocol === 'https:') {
    // ok
  } else if (allowLocalHttp) {
    // ok
  } else if (protocol === 'http:') {
    throw new Error('Webhook URL must use https (set WEBHOOK_ALLOW_HTTP_LOCAL=1 for loopback http)');
  } else {
    throw new Error('Webhook URL must use https');
  }

  if (parsed.username || parsed.password) {
    throw new Error('Webhook URL must not include credentials');
  }

  const hostname = parsed.hostname.replace(/^\[|\]$/g, '');
  if (!hostname) throw new Error('Invalid webhook URL host');

  // Literal IP hosts: check before DNS.
  if (net.isIP(hostname)) {
    const allowLoopback = allowHttpLocal && isLoopbackIpAddress(hostname);
    if (isBlockedIpAddress(hostname) && !allowLoopback) {
      throw new Error(`Webhook URL resolves to a blocked address (${hostname})`);
    }
    return { url: parsed, addresses: [hostname], pinnedAddress: hostname };
  }

  let records;
  try {
    records = await dnsLookup(hostname, { all: true, verbatim: true });
  } catch (error) {
    throw new Error(`Webhook DNS lookup failed: ${error.code || error.message}`);
  }

  const list = Array.isArray(records) ? records : records ? [records] : [];
  if (list.length === 0) {
    throw new Error('Webhook DNS lookup returned no addresses');
  }

  const addresses = [];
  for (const record of list) {
    const address = typeof record === 'string' ? record : record.address;
    if (!address) continue;
    const allowLoopback = allowHttpLocal && loopbackHost && isLoopbackIpAddress(address);
    if (isBlockedIpAddress(address) && !allowLoopback) {
      throw new Error(`Webhook URL resolves to a blocked address (${address})`);
    }
    addresses.push(address);
  }

  if (addresses.length === 0) {
    throw new Error('Webhook DNS lookup returned no addresses');
  }

  // All addresses are public (or allowed loopback); pin the first to avoid a second DNS lookup.
  return { url: parsed, addresses, pinnedAddress: addresses[0] };
}

/**
 * Validate webhook URL scheme and resolved addresses (fail closed).
 * @returns {Promise<URL>}
 */
export async function assertSafeWebhookUrl(
  rawUrl,
  {
    allowHttpLocal = String(process.env.WEBHOOK_ALLOW_HTTP_LOCAL || '') === '1',
    dnsLookup = defaultDnsLookup
  } = {}
) {
  const target = await resolveSafeWebhookTarget(rawUrl, { allowHttpLocal, dnsLookup });
  return target.url;
}

/**
 * Build a URL that connects to a pinned IP while preserving path/query/port/protocol.
 * Callers must set Host + TLS servername to the original hostname.
 */
export function buildPinnedWebhookUrl(parsedUrl, pinnedAddress) {
  const pinned = new URL(String(parsedUrl));
  pinned.hostname = pinnedAddress;
  return pinned;
}

/**
 * Default transport: connect to the pinned IP with original Host / TLS SNI.
 * Does not re-resolve DNS (prevents rebinding between assert and connect).
 */
export function pinnedWebhookFetch(requestUrl, options = {}) {
  const parsed = new URL(String(requestUrl));
  const isHttps = parsed.protocol === 'https:';
  const transport = isHttps ? https : http;
  const connectHost = parsed.hostname.replace(/^\[|\]$/g, '');
  const port = parsed.port ? Number(parsed.port) : isHttps ? 443 : 80;
  const path = `${parsed.pathname || '/'}${parsed.search || ''}`;
  const headers = { ...(options.headers || {}) };
  const servername = options.servername || headers.Host || headers.host || connectHost;
  // Ensure Host header reflects the original hostname when provided via servername/options.
  if (!headers.Host && !headers.host) {
    headers.Host = servername;
  }

  const signal = options.signal;
  const body = options.body;

  return new Promise((resolve, reject) => {
    let settled = false;
    const fail = (error) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(error);
    };
    const succeed = (value) => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(value);
    };

    const req = transport.request(
      {
        protocol: parsed.protocol,
        hostname: connectHost,
        port,
        path,
        method: options.method || 'GET',
        headers,
        servername: isHttps ? String(servername).replace(/:\d+$/, '').replace(/^\[|\]$/g, '') : undefined,
        timeout: FETCH_TIMEOUT_MS
      },
      (res) => {
        succeed({
          status: res.statusCode || 0,
          ok: (res.statusCode || 0) >= 200 && (res.statusCode || 0) < 300,
          headers: res.headers,
          body: res,
          async text() {
            return readLimitedStream(res, MAX_RESPONSE_BODY_BYTES);
          }
        });
      }
    );

    const onAbort = () => {
      const error = new Error('Webhook request timed out');
      error.name = signal?.reason?.name === 'TimeoutError' ? 'TimeoutError' : 'AbortError';
      req.destroy(error);
      fail(error);
    };

    function cleanup() {
      if (signal) {
        signal.removeEventListener?.('abort', onAbort);
      }
      req.removeAllListeners('timeout');
      req.removeAllListeners('error');
    }

    if (signal) {
      if (signal.aborted) {
        onAbort();
        return;
      }
      signal.addEventListener('abort', onAbort, { once: true });
    }

    req.on('timeout', () => {
      const error = new Error('Webhook request timed out');
      error.name = 'TimeoutError';
      req.destroy(error);
      fail(error);
    });
    req.on('error', (error) => {
      if (error?.name === 'TimeoutError' || error?.name === 'AbortError') {
        fail(error);
        return;
      }
      fail(error);
    });

    if (body != null && body !== '') {
      req.write(body);
    }
    req.end();
  });
}

export async function deliverOne(item, {
  fetchImpl = pinnedWebhookFetch,
  completeSuccess = completeWebhookDeliverySuccess,
  completeFailure = completeWebhookDeliveryFailure,
  dnsLookup = defaultDnsLookup,
  allowHttpLocal = String(process.env.WEBHOOK_ALLOW_HTTP_LOCAL || '') === '1',
  nowSeconds = () => Math.floor(Date.now() / 1000),
  logger = console
} = {}) {
  const delivery = item?.delivery;
  const webhook = item?.webhook;
  const deliveryId = delivery?.id;

  if (!deliveryId) {
    logger.warn?.('webhook deliverOne missing delivery id');
    return null;
  }

  const url = webhook?.url;
  const secret = webhook?.secret;
  if (!url || !secret) {
    return completeFailure(deliveryId, {
      error: 'Webhook target missing url or secret',
      permanent: true
    });
  }

  let target;
  try {
    target = await resolveSafeWebhookTarget(url, { allowHttpLocal, dnsLookup });
  } catch (error) {
    return completeFailure(deliveryId, {
      error: error.message || 'Webhook URL blocked',
      permanent: true
    });
  }

  const rawBody = delivery.payloadJson || '{}';
  let eventHeader = 'email.sent';
  try {
    const payload = JSON.parse(rawBody);
    eventHeader = payload.type || eventTypeForStatus(delivery.eventType) || eventHeader;
  } catch {
    eventHeader = eventTypeForStatus(delivery.eventType) || eventHeader;
  }

  const signature = signWebhookBody(rawBody, secret, nowSeconds());
  const originalHost = target.url.host;
  const originalHostname = target.url.hostname.replace(/^\[|\]$/g, '');
  const pinnedUrl = buildPinnedWebhookUrl(target.url, target.pinnedAddress);
  const headers = {
    'Content-Type': 'application/json',
    'User-Agent': USER_AGENT,
    Host: originalHost,
    'X-MailHub-Signature': signature,
    'X-MailHub-Event': eventHeader,
    'X-MailHub-Delivery': `whd_${deliveryId}`
  };

  try {
    const response = await fetchImpl(pinnedUrl.href, {
      method: 'POST',
      headers,
      body: rawBody,
      redirect: 'manual',
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      // Used by pinnedWebhookFetch; ignored by plain fetch mocks.
      servername: originalHostname,
      pinnedAddress: target.pinnedAddress
    });
    const status = Number(response?.status) || 0;
    const bodyPreview = await readBodyPreview(response);
    if (status >= 200 && status < 300) {
      return completeSuccess(deliveryId, {
        responseStatus: status,
        bodyPreview
      });
    }
    return completeFailure(deliveryId, {
      responseStatus: status || null,
      bodyPreview,
      error: `HTTP ${status || 'error'}`
    });
  } catch (error) {
    return completeFailure(deliveryId, {
      error: error.name === 'TimeoutError' || error.name === 'AbortError'
        ? 'Webhook request timed out'
        : error.message || 'Webhook request failed'
    });
  }
}

export async function processWebhookBatch({
  fetchImpl = pinnedWebhookFetch,
  batchSize = DEFAULT_BATCH_SIZE,
  claim = claimWebhookDeliveries,
  completeSuccess = completeWebhookDeliverySuccess,
  completeFailure = completeWebhookDeliveryFailure,
  reap = reapExpiredWebhookProcessing,
  dnsLookup = defaultDnsLookup,
  allowHttpLocal = String(process.env.WEBHOOK_ALLOW_HTTP_LOCAL || '') === '1',
  nowSeconds = () => Math.floor(Date.now() / 1000),
  logger = console
} = {}) {
  try {
    reap();
  } catch (error) {
    logger.warn?.(`webhook reap failed: ${error.message}`);
  }

  let claimed = [];
  try {
    claimed = claim(batchSize) || [];
  } catch (error) {
    logger.warn?.(`webhook claim failed: ${error.message}`);
    return { claimed: 0, processed: 0 };
  }

  let processed = 0;
  for (const item of claimed) {
    try {
      await deliverOne(item, {
        fetchImpl,
        completeSuccess,
        completeFailure,
        dnsLookup,
        allowHttpLocal,
        nowSeconds,
        logger
      });
      processed += 1;
    } catch (error) {
      logger.warn?.(`webhook deliver failed: ${error.message}`);
      try {
        if (item?.delivery?.id) {
          completeFailure(item.delivery.id, {
            error: error.message || 'Webhook deliver failed'
          });
        }
      } catch {
        // ignore secondary failures
      }
    }
  }

  return { claimed: claimed.length, processed };
}

export function startWebhookWorker({
  enabled = true,
  intervalMs = DEFAULT_INTERVAL_MS,
  batchSize = DEFAULT_BATCH_SIZE,
  fetchImpl = pinnedWebhookFetch,
  logger = console
} = {}) {
  if (!enabled) return null;
  if (workerHandle) return workerHandle;

  const state = {
    stopped: false,
    running: false
  };
  const pollIntervalMs = safePositiveInt(intervalMs, DEFAULT_INTERVAL_MS);
  const size = safePositiveInt(batchSize, DEFAULT_BATCH_SIZE);

  async function poll() {
    if (state.stopped || state.running) return;
    state.running = true;
    try {
      await processWebhookBatch({
        fetchImpl,
        batchSize: size,
        logger
      });
    } catch (error) {
      logger.warn?.(`webhook worker poll failed: ${error.message}`);
    } finally {
      state.running = false;
    }
  }

  const timer = setInterval(poll, pollIntervalMs);
  timer.unref?.();
  setTimeout(poll, 2000).unref?.();

  workerHandle = {
    stop() {
      state.stopped = true;
      clearInterval(timer);
      if (workerHandle === this) workerHandle = null;
    },
    poll
  };
  return workerHandle;
}

export function stopWebhookWorker() {
  if (!workerHandle) return;
  workerHandle.stop();
  workerHandle = null;
}

async function defaultDnsLookup(hostname, options) {
  return dns.promises.lookup(hostname, options);
}

/**
 * Read at most MAX_RESPONSE_BODY_BYTES from the response, then abort the rest.
 * Prefer body streams so large payloads never buffer fully into memory.
 */
async function readBodyPreview(response) {
  if (!response) return '';
  try {
    if (response.body && typeof response.body.getReader === 'function') {
      return await readLimitedWebStream(response.body, MAX_RESPONSE_BODY_BYTES);
    }
    if (response.body && typeof response.body.on === 'function') {
      return await readLimitedStream(response.body, MAX_RESPONSE_BODY_BYTES);
    }
    if (typeof response.text === 'function') {
      const text = await response.text();
      return String(text || '').slice(0, MAX_RESPONSE_BODY_BYTES);
    }
  } catch {
    return '';
  }
  return '';
}

async function readLimitedWebStream(stream, maxBytes) {
  const reader = stream.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (total < maxBytes) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      const chunk = Buffer.from(value);
      chunks.push(chunk);
      total += chunk.byteLength;
      if (total >= maxBytes) break;
    }
  } finally {
    try {
      await reader.cancel();
    } catch {
      // ignore cancel errors
    }
  }
  if (chunks.length === 0) return '';
  return Buffer.concat(chunks).subarray(0, maxBytes).toString('utf8');
}

function readLimitedStream(stream, maxBytes) {
  return new Promise((resolve) => {
    if (!stream || typeof stream.on !== 'function') {
      resolve('');
      return;
    }

    const chunks = [];
    let total = 0;
    let settled = false;

    const finish = () => {
      if (settled) return;
      settled = true;
      stream.removeListener?.('data', onData);
      stream.removeListener?.('end', onEnd);
      stream.removeListener?.('error', onEnd);
      stream.removeListener?.('close', onEnd);
      if (typeof stream.destroy === 'function' && !stream.destroyed) {
        try {
          stream.destroy();
        } catch {
          // ignore
        }
      }
      if (chunks.length === 0) {
        resolve('');
        return;
      }
      resolve(Buffer.concat(chunks).subarray(0, maxBytes).toString('utf8'));
    };

    const onData = (chunk) => {
      if (settled) return;
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      const remaining = maxBytes - total;
      if (remaining <= 0) {
        finish();
        return;
      }
      if (buf.byteLength > remaining) {
        chunks.push(buf.subarray(0, remaining));
        total += remaining;
        finish();
        return;
      }
      chunks.push(buf);
      total += buf.byteLength;
      if (total >= maxBytes) finish();
    };
    const onEnd = () => finish();

    // Already flowing / ended
    if (stream.readableEnded || stream.destroyed) {
      finish();
      return;
    }

    stream.on('data', onData);
    stream.on('end', onEnd);
    stream.on('error', onEnd);
    stream.on('close', onEnd);
  });
}

function safePositiveInt(value, fallback) {
  const number = Number(value);
  return Number.isFinite(number) && number > 0 ? Math.floor(number) : fallback;
}
