export type ViewKey =
  | 'dashboard'
  | 'domains'
  | 'dns-api'
  | 'smtp'
  | 'tokens'
  | 'logs'
  | 'webhooks'
  | 'settings';

export type DomainMode = 'list' | 'detail';

export interface User {
  id: number;
  username: string;
  email: string;
  role: 'admin' | 'user';
  status: 'active' | 'disabled';
}

export interface RuntimeConfig {
  appBaseUrl: string;
  mailHostname: string;
  sendingIp: string;
  defaultSpfMechanisms: string;
  dmarcPolicy: string;
  dmarcRua: string;
  sendRequiresVerified: boolean;
  submission?: {
    enabled: boolean;
    host: string;
    ports: Array<{ port: number; protocol: string }>;
    username: string;
    passwordSet: boolean;
    tls: boolean;
    requireTlsForAuth: boolean;
  };
  apiTokenSet?: boolean;
  usingDefaultAdminPassword?: boolean;
}

export interface DnsRecord {
  key: string;
  label: string;
  host: string;
  type: string;
  value?: string;
  status?: string;
  current?: string | string[];
  warnings?: string[];
  managed?: boolean;
}

export interface DomainStatus {
  checkedAt?: string;
  verified?: boolean;
  records?: DnsRecord[];
  optionalRecords?: DnsRecord[];
  warnings?: string[];
  live?: Record<string, string[]>;
  apply?: {
    ok: boolean;
    results?: Array<{
      key: string;
      type: string;
      host: string;
      ok: boolean;
      skipped?: boolean;
      detail?: string;
      error?: string;
    }>;
  };
}

export interface Domain {
  id: number;
  userId: number;
  dnsCredentialId: number | null;
  domain: string;
  selector: string;
  verificationToken: string;
  dkimPublic: string;
  senderHost: string;
  sendingIp: string;
  spfExtra: string;
  dmarcPolicy: string;
  dmarcRua: string;
  status: DomainStatus;
  createdAt: string;
  updatedAt: string;
}

export interface DnsCredential {
  id: number;
  name: string;
  provider: 'cloudflare' | 'aliyun' | 'dnspod' | string;
  zoneName: string;
  defaultTtl: number;
  createdAt: string;
  updatedAt: string;
}

export interface SmtpCredential {
  id?: number;
  username: string;
  password?: string;
  passwordSet?: boolean;
  updatedAt?: string;
}

export interface ApiToken {
  id: number;
  name: string;
  tokenPrefix: string;
  token?: string;
  lastUsedAt?: string;
  createdAt: string;
}

export interface DeliveryLogEntry {
  at: string;
  phase: 'connect' | 'smtp' | 'auth' | 'envelope' | 'data' | 'queue' | 'quit' | 'error' | string;
  direction?: 'client' | 'server' | 'system' | string;
  command?: string;
  response?: string;
  message?: string;
  code?: number;
  ok?: boolean;
  messageBytes?: number;
}

export interface DeliveryAttempt {
  at: string;
  source?: string;
  queueId: string;
  recipient?: string;
  relay?: string;
  dsn?: string;
  status: string;
  response?: string;
  raw?: string;
}

export interface SendEvent {
  id: number;
  userId: number;
  domainId: number | null;
  domain?: string;
  sender: string;
  recipients: string[];
  subject: string;
  status: string;
  detail: string;
  queueId?: string;
  deliveryLog?: DeliveryLogEntry[];
  deliveryAttempts?: DeliveryAttempt[];
  deliveredAt?: string;
  createdAt: string;
}

export interface Analytics {
  windowDays: number;
  summary: {
    total: number;
    queued: number;
    failed: number;
    recipients: number;
    today: number;
    last7Days: number;
    successRate: number;
    domains: number;
    verifiedDomains: number;
  };
  byDay: Array<{
    day: string;
    date?: string;
    total: number;
    queued: number;
    failed: number;
    recipients: number;
  }>;
  byDomain: Array<{
    domain: string;
    total: number;
    queued: number;
    failed: number;
    recipients: number;
  }>;
  byStatus: Array<{ status: string; total: number }>;
  hourly: Array<{ hour: number; total: number; queued: number; failed: number }>;
  recentFailures: SendEvent[];
}

export interface AppData {
  me: User | null;
  config: RuntimeConfig | null;
  domains: Domain[];
  events: SendEvent[];
  analytics: Analytics | null;
  smtpCredential: SmtpCredential | null;
  dnsCredentials: DnsCredential[];
  apiTokens: ApiToken[];
  settings: RuntimeConfig | null;
  users: User[];
}

export interface AddDomainPayload {
  domain: string;
  senderHost?: string;
  sendingIp?: string;
  dnsCredentialId?: number | string;
  selector?: string;
  dmarcPolicy?: string;
  spfExtra?: string;
  immediateCheck?: boolean;
}

export interface DomainPatchPayload {
  selector?: string;
  dnsCredentialId?: number | string | null;
  senderHost?: string;
  sendingIp?: string;
  spfExtra?: string;
  dmarcPolicy?: string;
  dmarcRua?: string;
}
