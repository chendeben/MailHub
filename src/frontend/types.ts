export type ViewKey =
  | 'dashboard'
  | 'domains'
  | 'dns-api'
  | 'smtp'
  | 'inbox'
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
  inboundMailboxes: number;
  inboundMessages: number;
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
  engagementTrackingEnabled: boolean;
  listUnsubscribeMailto: string;
  listUnsubscribeUrl: string;
  listUnsubscribePostEnabled: boolean;
  feedbackIdEnabled: boolean;
  reportAbuseTo: string;
  csaComplaintsTo: string;
  bounceAddress: string;
  bounceEnvelopeEnabled: boolean;
  systemChecks?: SystemChecks;
  submission?: {
    enabled: boolean;
    host: string;
    ports: Array<{ port: number; protocol: string }>;
    username: string;
    passwordSet: boolean;
    inboundEnabled: boolean;
    tls: boolean;
    requireTlsForAuth: boolean;
  };
  mailAccess?: {
    host: string;
    tls: boolean;
    requireTlsForAuth: boolean;
    imap: {
      enabled: boolean;
      ports: Array<{ port: number; protocol: string }>;
    };
    pop3: {
      enabled: boolean;
      ports: Array<{ port: number; protocol: string }>;
    };
  };
  apiTokenSet?: boolean;
  usingDefaultAdminPassword?: boolean;
}

export interface SystemChecks {
  checkedAt: string;
  ptr: DnsRecord;
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
  catchAllAddress: string;
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
  inboundMailboxes: InboundMailbox[];
  inboundMessageCount: number;
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
  scopes: Array<'send' | 'mailboxes:read' | 'mailboxes:write' | string>;
  expiresAt?: string | null;
  revokedAt?: string | null;
  revokedReason?: string;
  status?: 'active' | 'expired' | 'revoked' | string;
  lastUsedAt?: string;
  createdAt: string;
}

export interface InboundMailbox {
  id: number;
  userId: number;
  domainId: number;
  domain: string;
  address: string;
  localPart: string;
  displayName: string;
  aliases: string[];
  forwardTo: string[];
  keepForwarded: boolean;
  quotaMb: number | null;
  passwordSet: boolean;
  passwordRecoverable: boolean;
  status: string;
  expiresAt?: string | null;
  temporary?: boolean;
  messageCount: number;
  unreadCount: number;
  lastMessageAt?: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface MailboxClientConfig {
  username: string;
  password?: string;
  incoming: {
    protocol: string;
    host: string;
    port: number;
    security: string;
    authMethod: string;
    username: string;
    password?: string;
  };
  pop3?: {
    protocol: string;
    host: string;
    port: number;
    security: string;
    authMethod: string;
    username: string;
    password?: string;
  };
  outgoing: {
    protocol: string;
    host: string;
    port: number;
    security: string;
    authMethod: string;
    username: string;
    password?: string;
  };
}

export interface InboundMessage {
  id: number;
  mailboxId: number;
  userId: number;
  domainId: number;
  domain: string;
  mailboxAddress: string;
  sender: string;
  recipients: string[];
  subject: string;
  messageId: string;
  preview: string;
  read: boolean;
  receivedAt: string;
  createdAt: string;
  updatedAt: string;
  rawMessage?: string;
  textBody?: string;
  htmlBody?: string;
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

export interface SendEventTimelineEntry {
  stage: string;
  at: string;
  tone: 'success' | 'warning' | 'error' | 'info' | 'neutral';
  status?: string;
  queueId?: string;
  recipient?: string;
  relay?: string;
  response?: string;
  webhookId?: number;
  responseStatus?: number | null;
  source?: string;
  targetOrigin?: string;
  trackingLinkId?: number | null;
}

export interface TrackingEvent {
  id: number;
  sendEventId: number;
  trackingLinkId?: number | null;
  eventType: 'open' | 'click';
  source: 'direct' | 'proxy' | 'scanner';
  occurredAt: string;
  userAgent?: string;
  targetOrigin?: string;
}

export interface TrackingLink {
  id: number;
  target: string;
  targetOrigin: string;
  clicks: number;
  firstClickedAt?: string | null;
  lastClickedAt?: string | null;
}

export interface TrackingSummary {
  totalOpens: number;
  totalClicks: number;
  uniqueOpen: boolean;
  uniqueClick: boolean;
  proxyOpens: number;
  scannerEvents: number;
  firstOpenedAt?: string | null;
  lastOpenedAt?: string | null;
  firstClickedAt?: string | null;
  lastClickedAt?: string | null;
}

export interface SendTracking {
  enabled: boolean;
  opens: boolean;
  clicks: boolean;
  messageLevel: boolean;
  summary?: TrackingSummary;
  events?: TrackingEvent[];
  eventCount?: number;
  eventsTruncated?: boolean;
  links?: TrackingLink[];
  linkCount?: number;
  linksTruncated?: boolean;
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
  webhookDeliveries?: WebhookDelivery[];
  tracking?: SendTracking;
  deliveredAt?: string;
  createdAt: string;
}

export interface Analytics {
  windowDays: number;
  summary: {
    total: number;
    submitted: number;
    queued: number;
    failed: number;
    accepted: number;
    delivered: number;
    pending: number;
    deferred: number;
    bounced: number;
    terminalFailed: number;
    recipients: number;
    today: number;
    last7Days: number;
    successRate: number;
    acceptanceRate: number;
    deliveryRate: number;
    failureRate: number;
    domains: number;
    verifiedDomains: number;
  };
  deliveryFunnel: Array<{
    stage: string;
    total: number;
    rate: number;
  }>;
  engagement: {
    trackedDelivered: number;
    totalOpens: number;
    uniqueOpens: number;
    proxyOpens: number;
    totalClicks: number;
    uniqueClicks: number;
    scannerEvents: number;
    openRate: number;
    clickRate: number;
    clickToOpenRate: number;
  };
  engagementByDay: Array<{
    day: string;
    opens: number;
    uniqueOpens: number;
    clicks: number;
    uniqueClicks: number;
    scannerEvents: number;
  }>;
  topLinks: Array<{
    fingerprint: string;
    target: string;
    targetOrigin: string;
    clicks: number;
    uniqueClicks: number;
    lastClickedAt: string;
  }>;
  byDay: Array<{
    day: string;
    date?: string;
    total: number;
    queued: number;
    failed: number;
    accepted?: number;
    delivered?: number;
    pending?: number;
    terminalFailed?: number;
    recipients: number;
  }>;
  byDomain: Array<{
    domain: string;
    total: number;
    queued: number;
    failed: number;
    accepted?: number;
    delivered?: number;
    pending?: number;
    terminalFailed?: number;
    recipients: number;
  }>;
  byStatus: Array<{ status: string; total: number }>;
  hourly: Array<{
    hour: number;
    total: number;
    queued: number;
    failed: number;
    accepted?: number;
    delivered?: number;
    pending?: number;
    terminalFailed?: number;
  }>;
  failureReasons: Array<{
    reason: string;
    total: number;
    statuses: Record<string, number>;
    lastSeenAt: string;
  }>;
  recentFailures: SendEvent[];
}

export interface AppData {
  me: User | null;
  config: RuntimeConfig | null;
  domains: Domain[];
  events: SendEvent[];
  analytics: Analytics | null;
  smtpCredential: SmtpCredential | null;
  smtpCredentials: SmtpCredential[];
  smtpRelays: SmtpRelay[];
  inboundMailboxes: InboundMailbox[];
  inboundMessages: InboundMessage[];
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
  catchAllAddress?: string;
}

export type WebhookEvent = 'sent' | 'bounced' | 'failed' | 'opened' | 'clicked' | 'received';
export type WebhookDeliveryStatus = 'pending' | 'processing' | 'success' | 'dead';

export interface Webhook {
  id: number;
  userId: number;
  domainId: number | null;
  mailboxId: number | null;
  name: string;
  url: string;
  secretPrefix: string;
  events: WebhookEvent[];
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
  /** Present only on create / rotate-secret responses. */
  secret?: string;
}

export interface WebhookPayload {
  name: string;
  url: string;
  events: WebhookEvent[];
  domainId?: number | string | null;
  mailboxId?: number | string | null;
  enabled?: boolean;
}

export interface WebhookPatchPayload {
  name?: string;
  url?: string;
  events?: WebhookEvent[];
  domainId?: number | string | null;
  mailboxId?: number | string | null;
  enabled?: boolean;
}

export interface WebhookDelivery {
  id: number;
  webhookId: number;
  userId: number;
  sendEventId: number;
  inboundMessageId?: number | null;
  eventType: WebhookEvent | string;
  payloadJson?: string;
  status: WebhookDeliveryStatus | string;
  attemptCount: number;
  nextAttemptAt?: string | null;
  lastAttemptAt?: string | null;
  responseStatus?: number | null;
  responseBodyPreview?: string;
  error?: string;
  createdAt: string;
}

export interface WebhookDeliveryFilters {
  status?: WebhookDeliveryStatus | string;
  webhookId?: number;
  eventType?: WebhookEvent | string;
  limit?: number;
}
