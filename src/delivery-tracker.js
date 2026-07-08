import { open, stat } from 'node:fs/promises';
import { updateSendEventDelivery } from './db.js';

const queueIdPattern = /\bqueued as\s+([A-Z0-9]{5,})\b/i;
const deliveryServicePattern = /postfix\/(?:smtp|lmtp|local|virtual|pipe)\[\d+\]:\s+([A-Z0-9]{5,}):\s+(.+)$/i;

export function extractQueueIdFromSmtpResponse(message) {
  const match = String(message || '').match(queueIdPattern);
  return match ? match[1].toUpperCase() : '';
}

export function parsePostfixLogLine(line) {
  const serviceMatch = String(line || '').match(deliveryServicePattern);
  if (!serviceMatch) return null;
  const queueId = serviceMatch[1].toUpperCase();
  const body = serviceMatch[2] || '';
  const status = fieldValue(body, 'status');
  if (!status) return null;
  const recipient = bracketFieldValue(body, 'to');
  const relay = fieldValue(body, 'relay');
  const dsn = fieldValue(body, 'dsn');
  const response = body.match(/\bstatus=[a-z]+\s+\((.*)\)\s*$/i)?.[1] || '';
  return {
    at: new Date().toISOString(),
    source: 'postfix',
    queueId,
    recipient,
    relay,
    dsn,
    status: normalizePostfixStatus(status),
    response,
    raw: String(line || '')
  };
}

export function startPostfixDeliveryTracker({
  enabled = true,
  logFile,
  pollIntervalMs = 5000,
  onDelivery = updateSendEventDelivery,
  logger = console
} = {}) {
  if (!enabled || !logFile) return null;
  const state = {
    offset: 0,
    carry: '',
    stopped: false,
    polling: false
  };

  async function poll() {
    if (state.stopped || state.polling) return;
    state.polling = true;
    try {
      const chunk = await readNewChunk(logFile, state);
      if (!chunk) return;
      const lines = `${state.carry}${chunk}`.split(/\r?\n/);
      state.carry = lines.pop() || '';
      for (const line of lines) {
        const event = parsePostfixLogLine(line);
        if (event) onDelivery(event.queueId, event);
      }
    } catch (error) {
      logger.warn?.(`Delivery tracker could not read Postfix log: ${error.message}`);
    } finally {
      state.polling = false;
    }
  }

  const timer = setInterval(poll, pollIntervalMs);
  timer.unref?.();
  poll();
  return {
    stop() {
      state.stopped = true;
      clearInterval(timer);
    },
    poll
  };
}

async function readNewChunk(logFile, state) {
  const info = await stat(logFile).catch((error) => {
    if (error.code === 'ENOENT') return null;
    throw error;
  });
  if (!info || !info.isFile()) return '';
  if (info.size < state.offset) state.offset = 0;
  if (info.size === state.offset) return '';
  const length = info.size - state.offset;
  const buffer = Buffer.alloc(length);
  const handle = await open(logFile, 'r');
  try {
    await handle.read(buffer, 0, length, state.offset);
  } finally {
    await handle.close();
  }
  state.offset = info.size;
  return buffer.toString('utf8');
}

function fieldValue(body, key) {
  return String(body || '').match(new RegExp(`\\b${key}=([^,\\s]+)`, 'i'))?.[1] || '';
}

function bracketFieldValue(body, key) {
  return String(body || '').match(new RegExp(`\\b${key}=<([^>]+)>`, 'i'))?.[1] || '';
}

function normalizePostfixStatus(status) {
  const value = String(status || '').toLowerCase();
  if (['sent', 'deferred', 'bounced'].includes(value)) return value;
  return value || 'unknown';
}
