import type {
  AddDomainPayload,
  ApiToken,
  Analytics,
  DnsCredential,
  Domain,
  DomainPatchPayload,
  RuntimeConfig,
  SendEvent,
  SmtpCredential,
  User
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
  analytics: (days = 30) => request<{ analytics: Analytics }>(`/api/analytics?days=${days}`),
  smtpCredential: () => request<{ credential: SmtpCredential | null }>('/api/smtp-credential'),
  saveSmtpCredential: (data: { username: string; password?: string }) =>
    request<{ credential: SmtpCredential }>('/api/smtp-credential', { method: 'PUT', data }),
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
  createApiToken: (name: string) =>
    request<{ token: ApiToken }>('/api/api-tokens', { method: 'POST', data: { name } }),
  deleteApiToken: (id: number) => request<{ deleted: boolean }>(`/api/api-tokens/${id}`, { method: 'DELETE' }),
  createDomain: (data: AddDomainPayload) => request<{ domain: Domain }>('/api/domains', { method: 'POST', data }),
  patchDomain: (id: number, data: DomainPatchPayload) =>
    request<{ domain: Domain }>(`/api/domains/${id}`, { method: 'PATCH', data }),
  checkDomain: (id: number) => request<{ domain: Domain }>(`/api/domains/${id}/check`, { method: 'POST' }),
  applyDns: (id: number) =>
    request<{ domain: Domain; apply?: Domain['status']['apply'] }>(`/api/domains/${id}/apply-dns`, { method: 'POST' }),
  rotateDkim: (id: number, selector?: string) =>
    request<{ domain: Domain }>(`/api/domains/${id}/rotate-dkim`, { method: 'POST', data: { selector } }),
  sendTest: (id: number, data: { from?: string; to: string; subject?: string; text?: string }) =>
    request<{ queued: boolean }>(`/api/domains/${id}/test-send`, { method: 'POST', data }),
  deleteDomain: (id: number) => request<{ deleted: boolean }>(`/api/domains/${id}`, { method: 'DELETE' }),
  adminSettings: () => request<{ settings: RuntimeConfig }>('/api/admin/settings'),
  saveAdminSettings: (data: Partial<RuntimeConfig>) =>
    request<{ settings: RuntimeConfig }>('/api/admin/settings', { method: 'PATCH', data }),
  adminUsers: () => request<{ users: User[] }>('/api/admin/users'),
  logout: () => request<{ ok: boolean }>('/api/logout', { method: 'POST' })
};
