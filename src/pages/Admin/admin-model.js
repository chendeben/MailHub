const USER_STATUS_META = {
  pending_email: { label: '待验证邮箱', color: 'gold' },
  pending_review: { label: '待管理员审核', color: 'blue' },
  active: { label: '正常', color: 'green' },
  disabled: { label: '已禁用', color: 'red' }
};

const MERGE_SUMMARY_ITEMS = [
  ['domains', '域名'],
  ['dnsCredentials', 'DNS 凭据'],
  ['apiTokens', 'API Token'],
  ['sendEvents', '发送记录'],
  ['smtpCredential', 'SMTP 凭据']
];

export function adminUserStatusMeta(status) {
  return USER_STATUS_META[status] || { label: String(status || '未知'), color: 'default' };
}

export function buildMergeConfirmationText(sourceUser, targetUser) {
  return `MERGE ${sourceUser?.username || sourceUser?.id || ''} INTO ${targetUser?.username || targetUser?.id || ''}`;
}

export function mergePreviewSummary(preview) {
  const counts = preview?.selectedCounts || {};
  return MERGE_SUMMARY_ITEMS.map(([key, label]) => ({
    key,
    label,
    count: Number(counts[key] || 0)
  }));
}

export function serializeSystemEmailPayload(values) {
  const payload = compactObject({
    host: values?.host,
    port: values?.port === '' || values?.port == null ? undefined : Number(values.port),
    secure: values?.secure,
    username: values?.username,
    password: values?.password,
    fromEmail: values?.fromEmail
  });

  if (typeof payload.password === 'string' && payload.password.trim() === '') {
    delete payload.password;
  }

  return payload;
}

export function serializeAuditFilters(filters) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filters || {})) {
    if (value === '' || value == null) {
      continue;
    }
    params.set(key, String(value));
  }
  return params.toString();
}

function compactObject(values) {
  return Object.fromEntries(
    Object.entries(values).filter(([, value]) => value !== '' && value != null)
  );
}
