export type ViewKey =
  | 'dashboard'
  | 'domains'
  | 'dns-api'
  | 'smtp'
  | 'tokens'
  | 'logs'
  | 'webhooks'
  | 'admin'
  | 'settings';

export type DomainMode = 'list' | 'detail';
export type UserStatus = 'pending_email' | 'pending_review' | 'active' | 'disabled';
export type UserRole = 'admin' | 'user';

export interface UserResourceCounts {
  domains: number;
  dnsCredentials: number;
  apiTokens: number;
  sendEvents: number;
  smtpCredential: number;
}

export interface User {
  id: number;
  username: string;
  email: string;
  role: UserRole;
  status: UserStatus;
  createdAt?: string;
  updatedAt?: string;
  resourceCounts?: UserResourceCounts;
}

export interface AdminUser extends User {
  resourceCounts: UserResourceCounts;
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
  smtpRelayId: number | null;
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
  userId?: number;
  name: string;
  provider: 'cloudflare' | 'aliyun' | 'dnspod' | string;
  zoneName: string;
  defaultTtl: number;
  credentialSet?: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface SmtpCredential {
  id?: number;
  userId?: number;
  username: string;
  password?: string;
  passwordSet?: boolean;
  passwordRecoverable?: boolean;
  createdAt?: string;
  updatedAt?: string;
}

export interface SmtpRelay {
  id: number;
  userId?: number;
  name: string;
  host: string;
  port: number;
  secure: boolean;
  username: string;
  password?: string;
  passwordSet: boolean;
  helo: string;
  isDefault: boolean;
  createdAt?: string;
  updatedAt?: string;
}

export interface SmtpRelayPayload {
  name: string;
  host: string;
  port: number | string;
  secure?: boolean;
  username?: string;
  password?: string;
  helo?: string;
  isDefault?: boolean;
}

export interface SystemEmailSettings {
  host: string;
  port: number;
  secure: boolean;
  username: string;
  password?: string;
  passwordSet: boolean;
  helo: string;
  fromEmail: string;
  fromName: string;
  testRecipient: string;
}

export interface AdminResourceInventory {
  users: AdminUserResourceGroup[];
  warnings: Array<{
    type: 'domain_dns_credential_owner_mismatch' | string;
    domainId: number;
    domain: string;
    domainUserId: number;
    dnsCredentialId: number;
    dnsCredentialUserId: number;
  }>;
}

export interface AdminUserResourceGroup {
  user: AdminUser;
  domains: Domain[];
  dnsCredentials: DnsCredential[];
  smtpCredential: SmtpCredential | null;
  apiTokens: ApiToken[];
  sendEventCount: number;
}

export interface UserMergeOptions {
  transferDomains: boolean;
  transferDnsCredentials: boolean;
  transferApiTokens: boolean;
  transferSendEvents: boolean;
  transferSmtpCredential: boolean;
  disableSource: boolean;
}

export interface UserMergePreview {
  sourceUser: User;
  targetUser: User;
  confirmationText: string;
  counts: UserResourceCounts;
  selectedCounts: UserResourceCounts;
  defaultOptions: UserMergeOptions;
  resources: {
    source: Omit<AdminUserResourceGroup, 'user'>;
    target: Omit<AdminUserResourceGroup, 'user'>;
  };
  smtp: {
    sourceCredential: SmtpCredential | null;
    targetCredential: SmtpCredential | null;
    conflict: boolean;
  };
  warnings: Array<{ type: string; message?: string }>;
}

export interface UserMergeResult {
  sourceUser: User;
  targetUser: User;
  counts: UserResourceCounts;
  warnings: UserMergePreview['warnings'];
}

export interface AuditLogEntry {
  id: number;
  actorUserId: number | null;
  action: string;
  targetType: string;
  targetId: string;
  targetUserId: number | null;
  summary: Record<string, unknown>;
  createdAt: string;
}

export interface ApiToken {
  id: number;
  userId?: number;
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
  smtpRelayId: number | null;
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
  smtpRelays: SmtpRelay[];
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
  smtpRelayId?: number | string | null;
  selector?: string;
  dmarcPolicy?: string;
  spfExtra?: string;
  immediateCheck?: boolean;
}

export interface DomainPatchPayload {
  selector?: string;
  dnsCredentialId?: number | string | null;
  smtpRelayId?: number | string | null;
  senderHost?: string;
  sendingIp?: string;
  spfExtra?: string;
  dmarcPolicy?: string;
  dmarcRua?: string;
}
