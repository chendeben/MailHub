import crypto from 'node:crypto';

export const TERMINAL_WEBHOOK_EVENTS = ['sent', 'bounced', 'failed'];
export const WEBHOOK_EVENTS = [...TERMINAL_WEBHOOK_EVENTS, 'opened', 'clicked', 'received'];
export const MAX_WEBHOOK_ATTEMPTS = 8;
export const WEBHOOK_LEASE_MS = 2 * 60 * 1000;

const BACKOFF_MS_TABLE = [
  60_000, // 1m
  300_000, // 5m
  1_800_000, // 30m
  7_200_000, // 2h
  21_600_000, // 6h
  43_200_000 // 12h (cap)
];

export function isTerminalWebhookStatus(status) {
  return TERMINAL_WEBHOOK_EVENTS.includes(status);
}

export function eventTypeForStatus(status) {
  if (status === 'sent') return 'email.sent';
  if (status === 'bounced') return 'email.bounced';
  if (status === 'failed') return 'email.failed';
  if (status === 'opened') return 'email.opened';
  if (status === 'clicked') return 'email.clicked';
  if (status === 'received') return 'email.received';
  return null;
}

/**
 * Domain-scoped enabled webhooks for an event win; otherwise account-level.
 * @param {{ accountWebhooks: any[]; domainWebhooks: any[]; eventType: string }} input
 */
export function resolveWebhooksForEvent({ accountWebhooks, domainWebhooks, eventType }) {
  const matches = (list) =>
    (list || []).filter(
      (w) =>
        w.enabled !== false &&
        w.enabled !== 'false' &&
        Array.isArray(w.events) &&
        w.events.includes(eventType)
    );
  const domainHits = matches(domainWebhooks);
  if (domainHits.length) return domainHits;
  return matches(accountWebhooks);
}

export function buildWebhookPayload({
  deliveryId,
  eventType,
  createdAt,
  sendEvent,
  inboundMessage = null,
  engagement = null,
  test = false
}) {
  if (inboundMessage) {
    const rfcMessageId = String(inboundMessage.messageId || '').trim();
    return {
      id: `whd_${deliveryId}`,
      type: String(eventType || '').startsWith('email.') ? eventType : eventTypeForStatus('received'),
      created_at: createdAt,
      data: {
        ...(test ? { test: true } : {}),
        message_id: rfcMessageId || (test ? 'mh-test' : `mh-in-${inboundMessage.id}`),
        rfc_message_id: rfcMessageId || null,
        inbound_message_id: inboundMessage.id,
        mailbox_id: inboundMessage.mailboxId,
        mailbox: inboundMessage.mailboxAddress || '',
        domain: inboundMessage.domain || '',
        from: inboundMessage.sender || '',
        to: inboundMessage.recipients || [],
        subject: inboundMessage.subject || '',
        text: inboundMessage.textBody || '',
        html: inboundMessage.htmlBody || '',
        received_at: inboundMessage.receivedAt || null
      }
    };
  }

  const status = sendEvent.status;
  const externalType = String(eventType || '').startsWith('email.')
    ? eventType
    : eventTypeForStatus(status) || eventType;
  return {
    id: `whd_${deliveryId}`,
    type: externalType,
    created_at: createdAt,
    data: {
      ...(test ? { test: true } : {}),
      message_id: test ? 'mh-test' : `mh-${sendEvent.id}`,
      send_event_id: sendEvent.id,
      queue_id: sendEvent.queueId || '',
      status,
      domain: sendEvent.domain || '',
      from: sendEvent.sender || '',
      to: sendEvent.recipients || [],
      subject: sendEvent.subject || '',
      detail: sendEvent.detail || '',
      delivered_at: sendEvent.deliveredAt || null,
      ...(engagement ? { engagement: publicEngagement(engagement) } : {})
    }
  };
}

/**
 * Stripe-style signature header: t=<unix>,v1=<hex hmac of `${t}.${rawBody}`>
 */
export function signWebhookBody(rawBody, secret, unixSeconds = Math.floor(Date.now() / 1000)) {
  const signed = `${unixSeconds}.${rawBody}`;
  const v1 = crypto.createHmac('sha256', secret).update(signed).digest('hex');
  return `t=${unixSeconds},v1=${v1}`;
}

/**
 * attemptCount after increment for failed path; attempt 1 → 60s, … cap 12h
 */
export function nextBackoffMs(attemptCount) {
  const index = Math.max(0, Math.min(BACKOFF_MS_TABLE.length - 1, attemptCount - 1));
  return BACKOFF_MS_TABLE[index];
}

/**
 * Validate and normalize a non-empty subset of terminal webhook events.
 * Preserves TERMINAL_WEBHOOK_EVENTS order and de-duplicates.
 */
export function normalizeWebhookEvents(input) {
  if (!Array.isArray(input)) {
    throw webhookEventsError();
  }
  const allowed = new Set(WEBHOOK_EVENTS);
  const seen = new Set();
  for (const item of input) {
    if (!allowed.has(item)) {
      throw webhookEventsError();
    }
    seen.add(item);
  }
  if (seen.size === 0) {
    throw webhookEventsError();
  }
  return WEBHOOK_EVENTS.filter((e) => seen.has(e));
}

export function parseWebhookEventsJson(json) {
  let parsed;
  try {
    parsed = typeof json === 'string' ? JSON.parse(json) : json;
  } catch {
    throw webhookEventsError();
  }
  return normalizeWebhookEvents(parsed);
}

function publicEngagement(engagement) {
  return {
    type: engagement.type,
    occurred_at: engagement.occurredAt,
    source: engagement.source,
    link_id: engagement.linkId ?? null,
    target_origin: engagement.targetOrigin || ''
  };
}

function webhookEventsError() {
  return new Error('events must be a non-empty array of sent|bounced|failed|opened|clicked|received');
}
