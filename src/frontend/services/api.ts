import type {
  AddDomainPayload,
  AdminResourceInventory,
  AdminUser,
  ApiToken,
  Analytics,
  AuditLogEntry,
  DnsCredential,
  Domain,
  DomainPatchPayload,
  InboundMailbox,
  InboundMessage,
  MailboxClientConfig,
  RuntimeConfig,
  SendEvent,
  SmtpCredential,
  SmtpRelay,
  SmtpRelayPayload,
  SystemEmailSettings,
  User,
  UserMergeOptions,
  UserMergePreview,
  UserMergeResult,
  UserRole,
  UserStatus,
  Webhook,
  WebhookDelivery,
  WebhookDeliveryFilters,
  WebhookPatchPayload,
  WebhookPayload
} from '../types';

interface RequestOptions extends RequestInit {
  data?: unknown;
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const headers = new Headers(options.headers);
  if (options.data !== undefined && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  const response = await send(path, {
    method: options.method || 'GET',
    headers,
    body: options.data === undefined ? options.body : JSON.stringify(options.data)
  });
  const text = response.text;
  const payload = text ? JSON.parse(text) : {};

  if (response.status < 200 || response.status >= 300) {
    throw new Error(payload.error || payload.message || requestFailedMessage(response.status));
  }

  return payload as T;
}

function send(
  path: string,
  options: { method: string; headers: Headers; body?: BodyInit | null }
): Promise<{ status: number; text: string }> {
  if (typeof globalThis.fetch === 'function') {
    return globalThis.fetch(path, {
      method: options.method,
      headers: options.headers,
      body: options.body
    }).then(async (response) => ({
      status: response.status,
      text: await response.text()
    }));
  }

  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open(options.method, path, true);
    options.headers.forEach((value, key) => xhr.setRequestHeader(key, value));
    xhr.onload = () => resolve({ status: xhr.status, text: xhr.responseText || '' });
    xhr.onerror = () => reject(new Error(networkFailedMessage()));
    xhr.send((options.body || null) as XMLHttpRequestBodyInit | null);
  });
}

function requestFailedMessage(status: number) {
  return currentLocale().startsWith('en') ? `Request failed: ${status}` : `请求失败：${status}`;
}

function networkFailedMessage() {
  return currentLocale().startsWith('en') ? 'Network request failed' : '网络请求失败';
}

function currentLocale() {
  return document.documentElement.lang || window.localStorage.getItem('mailhub.locale') || 'zh-CN';
}

export const api = {
  me: () => request<{ user: User }>('/api/me'),
  config: () => request<RuntimeConfig>('/api/config'),
  domains: () => request<{ domains: Domain[] }>('/api/domains'),
  events: () => request<{ events: SendEvent[] }>('/api/events'),
  event: (id: number) => request<{ event: SendEvent | null }>(`/api/events/${id}`),
  inboundMailboxes: () => request<{ mailboxes: InboundMailbox[] }>('/api/inbound-mailboxes'),
  createInboundMailbox: (data: {
    address: string;
    displayName?: string;
    password: string;
    aliases?: string | string[];
    forwardTo?: string | string[];
    keepForwarded?: boolean;
    quotaMb?: number | string | null;
  }) => request<{ mailbox: InboundMailbox; clientConfig?: MailboxClientConfig }>('/api/inbound-mailboxes', { method: 'POST', data }),
  updateInboundMailbox: (id: number, data: Partial<{
    displayName: string;
    password: string;
    aliases: string | string[];
    forwardTo: string | string[];
    keepForwarded: boolean;
    quotaMb: number | string | null;
    status: string;
  }>) => request<{ mailbox: InboundMailbox; clientConfig?: MailboxClientConfig }>(`/api/inbound-mailboxes/${id}`, {
    method: 'PATCH',
    data
  }),
  inboundMessages: (mailboxId?: number | null) => {
    const query = mailboxId ? `?mailboxId=${mailboxId}` : '';
    return request<{ messages: InboundMessage[] }>(`/api/inbound-messages${query}`);
  },
  inboundMessage: (id: number) => request<{ message: InboundMessage | null }>(`/api/inbound-messages/${id}`),
  markInboundMessageRead: (id: number, read = true) =>
    request<{ message: InboundMessage | null }>(`/api/inbound-messages/${id}`, { method: 'PATCH', data: { read } }),
  analytics: (days = 7) => request<{ analytics: Analytics }>(`/api/analytics?days=${days}`),
  smtpCredential: () => request<{ credential: SmtpCredential | null }>('/api/smtp-credential'),
  saveSmtpCredential: (data: { username: string; password?: string }) =>
    request<{ credential: SmtpCredential }>('/api/smtp-credential', { method: 'PUT', data }),
  smtpCredentials: () => request<{ credentials: SmtpCredential[] }>('/api/smtp-credentials'),
  smtpCredentialDetail: (id: number) => request<{ credential: SmtpCredential }>(`/api/smtp-credentials/${id}`),
  saveSmtpLoginCredential: (data: { username: string; password?: string }, id?: number) =>
    request<{ credential: SmtpCredential }>(id ? `/api/smtp-credentials/${id}` : '/api/smtp-credentials', {
      method: id ? 'PATCH' : 'POST',
      data
    }),
  deleteSmtpCredential: (id: number) =>
    request<{ deleted: boolean }>(`/api/smtp-credentials/${id}`, { method: 'DELETE' }),
  smtpRelays: () => request<{ relays: SmtpRelay[] }>('/api/smtp-relays'),
  smtpRelay: (id: number) => request<{ relay: SmtpRelay }>(`/api/smtp-relays/${id}`),
  saveSmtpRelay: (data: SmtpRelayPayload, id?: number) =>
    request<{ relay: SmtpRelay }>(id ? `/api/smtp-relays/${id}` : '/api/smtp-relays', {
      method: id ? 'PATCH' : 'POST',
      data
    }),
  deleteSmtpRelay: (id: number) =>
    request<{ deleted: boolean }>(`/api/smtp-relays/${id}`, { method: 'DELETE' }),
  dnsCredentials: () => request<{ credentials: DnsCredential[] }>('/api/dns-credentials'),
  saveDnsCredential: (data: Record<string, unknown>, id?: number) =>
    request<{ credential: DnsCredential }>(id ? `/api/dns-credentials/${id}` : '/api/dns-credentials', {
      method: id ? 'PATCH' : 'POST',
      data
    }),
  testDnsCredential: (id: number) =>
    request<{ ok: boolean; detail?: string; provider?: string; error?: string }>(`/api/dns-credentials/${id}/test`, {
      method: 'POST'
    }),
  deleteDnsCredential: (id: number) =>
    request<{ deleted: boolean }>(`/api/dns-credentials/${id}`, { method: 'DELETE' }),
  apiTokens: () => request<{ tokens: ApiToken[] }>('/api/api-tokens'),
  createApiToken: (data: { name: string; scopes?: string[]; expiresAt?: string | null }) =>
    request<{ token: ApiToken }>('/api/api-tokens', { method: 'POST', data }),
  updateApiToken: (id: number, data: { name?: string; scopes?: string[]; expiresAt?: string | null }) =>
    request<{ token: ApiToken }>(`/api/api-tokens/${id}`, { method: 'PATCH', data }),
  deleteApiToken: (id: number) => request<{ deleted: boolean; revoked: boolean; token?: ApiToken | null }>(`/api/api-tokens/${id}`, { method: 'DELETE' }),
  createDomain: (data: AddDomainPayload) => request<{ domain: Domain }>('/api/domains', { method: 'POST', data }),
  patchDomain: (id: number, data: DomainPatchPayload) =>
    request<{ domain: Domain }>(`/api/domains/${id}`, { method: 'PATCH', data }),
  checkDomain: (id: number) => request<{ domain: Domain }>(`/api/domains/${id}/check`, { method: 'POST' }),
  applyDns: (id: number) =>
    request<{ domain: Domain; apply?: Domain['status']['apply'] }>(`/api/domains/${id}/apply-dns`, { method: 'POST' }),
  rotateDkim: (id: number, selector?: string) =>
    request<{ domain: Domain }>(`/api/domains/${id}/rotate-dkim`, { method: 'POST', data: { selector } }),
  sendTest: (
    id: number,
    data: {
      from?: string;
      to: string;
      subject?: string;
      text?: string;
      html?: string;
      tracking?: boolean | { opens?: boolean; clicks?: boolean };
      smtpRelayId?: number | string | null;
    }
  ) =>
    request<{ queued: boolean }>(`/api/domains/${id}/test-send`, { method: 'POST', data }),
  deleteDomain: (id: number) => request<{ deleted: boolean }>(`/api/domains/${id}`, { method: 'DELETE' }),
  adminSettings: () => request<{ settings: RuntimeConfig }>('/api/admin/settings'),
  saveAdminSettings: (data: Partial<RuntimeConfig>) =>
    request<{ settings: RuntimeConfig }>('/api/admin/settings', { method: 'PATCH', data }),
  adminUsers: () => request<{ users: AdminUser[] }>('/api/admin/users'),
  updateAdminUser: (id: number, data: { role?: UserRole; status?: UserStatus; password?: string }) =>
    request<{ user: AdminUser }>(`/api/admin/users/${id}`, { method: 'PATCH', data }),
  approveAdminUser: (id: number) =>
    request<{ user: AdminUser }>(`/api/admin/users/${id}/approve`, { method: 'POST' }),
  resendAdminVerification: (id: number) =>
    request<{
      verificationEmailSent?: boolean;
      message: string;
      result?: SystemMailActionResult;
    }>(`/api/admin/users/${id}/resend-verification`, { method: 'POST' }),
  sendAdminPasswordReset: (id: number) =>
    request<{ result: SystemMailActionResult }>(`/api/admin/users/${id}/password-reset`, { method: 'POST' }),
  setAdminTemporaryPassword: (id: number, password: string) =>
    request<{ user: AdminUser }>(`/api/admin/users/${id}/temporary-password`, {
      method: 'POST',
      data: { password }
    }),
  adminResources: () => request<{ inventory: AdminResourceInventory }>('/api/admin/resources'),
  transferAdminDomain: (
    id: number,
    data: { targetUserId: number; dnsCredentialMode?: 'domain_only' | 'with_dns_credential' | 'clear_dns_credential' }
  ) => request<{ domain: Domain }>(`/api/admin/resources/domains/${id}/transfer`, { method: 'POST', data }),
  transferAdminDnsCredential: (id: number, data: { targetUserId: number }) =>
    request<{ credential: DnsCredential }>(`/api/admin/resources/dns-credentials/${id}/transfer`, {
      method: 'POST',
      data
    }),
  transferAdminApiTokens: (data: { tokenIds: number[]; targetUserId: number }) =>
    request<{ tokens: ApiToken[] }>('/api/admin/resources/api-tokens/transfer', { method: 'POST', data }),
  previewUserMerge: (data: { sourceUserId: number; targetUserId: number }) =>
    request<{ preview: UserMergePreview }>('/api/admin/migrations/user-merge/preview', { method: 'POST', data }),
  executeUserMerge: (data: {
    sourceUserId: number;
    targetUserId: number;
    options: Partial<UserMergeOptions>;
    confirmation: string;
  }) => request<{ result: UserMergeResult }>('/api/admin/migrations/user-merge/execute', { method: 'POST', data }),
  adminSystemEmail: () => request<{ settings: SystemEmailSettings }>('/api/admin/system-email'),
  saveAdminSystemEmail: (data: Partial<SystemEmailSettings>) =>
    request<{ settings: SystemEmailSettings }>('/api/admin/system-email', { method: 'PATCH', data }),
  testAdminSystemEmail: (to?: string) =>
    request<{ result: SystemMailActionResult }>('/api/admin/system-email/test', {
      method: 'POST',
      data: to ? { to } : {}
    }),
  adminAuditLogs: (query = '') =>
    request<{ logs: AuditLogEntry[] }>(`/api/admin/audit-logs${query ? `?${query}` : ''}`),
  resendVerification: (email: string) =>
    request<{ message: string }>('/api/auth/resend-verification', { method: 'POST', data: { email } }),
  forgotPassword: (email: string) =>
    request<{ message: string }>('/api/auth/forgot-password', { method: 'POST', data: { email } }),
  resetPassword: (token: string, password: string) =>
    request<{ message: string }>('/api/auth/reset-password', { method: 'POST', data: { token, password } }),
  logout: () => request<{ ok: boolean }>('/api/logout', { method: 'POST' }),
  webhooks: (domainId?: number | null, mailboxId?: number) => {
    const params = new URLSearchParams();
    if (domainId === null) params.set('domainId', 'null');
    else if (domainId !== undefined) params.set('domainId', String(domainId));
    if (mailboxId !== undefined) params.set('mailboxId', String(mailboxId));
    const query = params.toString();
    return request<{ webhooks: Webhook[] }>(`/api/webhooks${query ? `?${query}` : ''}`);
  },
  createWebhook: (data: WebhookPayload) =>
    request<{ webhook: Webhook }>('/api/webhooks', { method: 'POST', data }),
  updateWebhook: (id: number, data: WebhookPatchPayload) =>
    request<{ webhook: Webhook }>(`/api/webhooks/${id}`, { method: 'PATCH', data }),
  deleteWebhook: (id: number) =>
    request<{ deleted: boolean }>(`/api/webhooks/${id}`, { method: 'DELETE' }),
  rotateWebhookSecret: (id: number) =>
    request<{ webhook: Webhook }>(`/api/webhooks/${id}/rotate-secret`, { method: 'POST' }),
  testWebhook: (id: number) =>
    request<{ delivery: WebhookDelivery }>(`/api/webhooks/${id}/test`, { method: 'POST' }),
  webhookDeliveries: (filters: WebhookDeliveryFilters = {}) => {
    const params = new URLSearchParams();
    if (filters.status) params.set('status', String(filters.status));
    if (filters.webhookId != null) params.set('webhookId', String(filters.webhookId));
    if (filters.eventType) params.set('eventType', String(filters.eventType));
    if (filters.limit != null) params.set('limit', String(filters.limit));
    const query = params.toString();
    return request<{ deliveries: WebhookDelivery[] }>(
      `/api/webhook-deliveries${query ? `?${query}` : ''}`
    );
  },
  replayWebhookDelivery: (id: number) =>
    request<{ delivery: WebhookDelivery }>(`/api/webhook-deliveries/${id}/replay`, { method: 'POST' })
};

interface SystemMailActionResult {
  ok: boolean;
  message: string;
  queueId?: string;
}
