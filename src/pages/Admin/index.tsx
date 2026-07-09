import {
  CheckCircleOutlined,
  MailOutlined,
  ReloadOutlined,
  SendOutlined,
  UserSwitchOutlined
} from '@ant-design/icons';
import {
  Alert,
  App as AntApp,
  Button,
  Checkbox,
  Descriptions,
  Form,
  Input,
  InputNumber,
  Modal,
  Select,
  Space,
  Switch,
  Table,
  Tabs,
  Tag,
  Typography
} from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { useEffect, useState } from 'react';

import { EmptyState } from '../../components/common/EmptyState';
import { PageHeader } from '../../components/common/PageHeader';
import { SectionCard } from '../../components/common/SectionCard';
import { StatusPill } from '../../components/common/StatusPill';
import {
  adminUserStatusMeta,
  buildMergeConfirmationText,
  mergePreviewSummary,
  serializeAuditFilters,
  serializeSystemEmailPayload
} from './admin-model.js';
import { useI18n } from '../../frontend/i18n/react';
import { api } from '../../frontend/services/api';
import type {
  AdminResourceInventory,
  AdminUser,
  AuditLogEntry,
  SystemEmailSettings,
  User,
  UserMergeOptions,
  UserMergePreview,
  UserRole,
  UserStatus
} from '../../frontend/types';

interface AdminPageProps {
  me: User | null;
}

const statusValues: UserStatus[] = ['pending_email', 'pending_review', 'active', 'disabled'];
const roleValues: UserRole[] = ['user', 'admin'];

const mergeOptionLabels: Array<[keyof UserMergeOptions, string]> = [
  ['transferDomains', '迁移域名'],
  ['transferDnsCredentials', '迁移 DNS 凭据'],
  ['transferApiTokens', '迁移 API Token'],
  ['transferSendEvents', '迁移发送记录'],
  ['transferSmtpCredential', '迁移 SMTP 凭据'],
  ['disableSource', '禁用源用户']
];

export default function AdminPage({ me }: AdminPageProps) {
  const { message, modal } = AntApp.useApp();
  const { t } = useI18n();
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [inventory, setInventory] = useState<AdminResourceInventory | null>(null);
  const [systemEmail, setSystemEmail] = useState<SystemEmailSettings | null>(null);
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);
  const [auditQuery, setAuditQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);

  useEffect(() => {
    if (me?.role === 'admin') void loadAdminData();
  }, [me?.role]);

  if (me?.role !== 'admin') {
    return (
      <Space direction="vertical" size={20} className="full-width">
        <PageHeader title={t('admin.title')} />
        <SectionCard>
          <Typography.Text type="secondary">{t('settings.noPermission')}</Typography.Text>
        </SectionCard>
      </Space>
    );
  }

  async function loadAdminData(query = auditQuery) {
    setLoading(true);
    try {
      const [usersResult, resourcesResult, emailResult, auditResult] = await Promise.all([
        api.adminUsers(),
        api.adminResources(),
        api.adminSystemEmail(),
        api.adminAuditLogs(query)
      ]);
      setUsers(usersResult.users || []);
      setInventory(resourcesResult.inventory || null);
      setSystemEmail(emailResult.settings || null);
      setAuditLogs(auditResult.logs || []);
    } catch (error) {
      message.error(error instanceof Error ? error.message : '管理员数据加载失败');
    } finally {
      setLoading(false);
    }
  }

  async function runAction(action: () => Promise<unknown>, success: string, refresh = true) {
    setActionLoading(true);
    try {
      await action();
      message.success(success);
      if (refresh) await loadAdminData();
    } catch (error) {
      message.error(error instanceof Error ? error.message : '操作失败');
    } finally {
      setActionLoading(false);
    }
  }

  function confirm(title: string, action: () => Promise<unknown>) {
    modal.confirm({
      title,
      okText: t('common.confirm'),
      cancelText: t('common.cancel'),
      onOk: action
    });
  }

  async function searchAuditLogs(query: string) {
    setAuditQuery(query);
    setLoading(true);
    try {
      const result = await api.adminAuditLogs(query);
      setAuditLogs(result.logs || []);
    } catch (error) {
      message.error(error instanceof Error ? error.message : '审计日志加载失败');
    } finally {
      setLoading(false);
    }
  }

  const tabItems = [
    {
      key: 'users',
      label: t('admin.users'),
      children: (
        <AdminUsers
          users={users}
          loading={loading || actionLoading}
          onApprove={(user) => confirm(`确认审批用户 ${user.username}？`, () =>
            runAction(() => api.approveAdminUser(user.id), '用户已审批')
          )}
          onResendVerification={(user) => runAction(() => api.resendAdminVerification(user.id), '验证邮件请求已提交')}
          onPasswordReset={(user) => confirm(`确认给 ${user.email} 发送密码重置邮件？`, () =>
            runAction(() => api.sendAdminPasswordReset(user.id), '密码重置邮件请求已提交')
          )}
          onTemporaryPassword={(user, password) => confirm(`确认为用户 ${user.username} 设置临时密码？`, () =>
            runAction(() => api.setAdminTemporaryPassword(user.id, password), '临时密码已设置')
          )}
          onUpdateUser={(user, patch) => confirm(`确认更新用户 ${user.username}？`, () =>
            runAction(() => api.updateAdminUser(user.id, patch), '用户已更新')
          )}
        />
      )
    },
    {
      key: 'resources',
      label: t('admin.resources'),
      children: (
        <AdminResources
          users={users}
          inventory={inventory}
          loading={loading || actionLoading}
          onTransferDomain={(domainId, values) =>
            runAction(() => api.transferAdminDomain(domainId, values), '域名已迁移')
          }
          onTransferDnsCredential={(credentialId, values) =>
            runAction(() => api.transferAdminDnsCredential(credentialId, values), 'DNS 凭据已迁移')
          }
          onTransferApiTokens={(values) =>
            runAction(() => api.transferAdminApiTokens(values), 'API Token 已迁移')
          }
        />
      )
    },
    {
      key: 'migration',
      label: t('admin.migration'),
      children: (
        <AdminMigration
          users={users}
          loading={loading || actionLoading}
          onPreview={(values) => api.previewUserMerge(values)}
          onExecute={(values) => runAction(() => api.executeUserMerge(values), '用户资源已合并')}
        />
      )
    },
    {
      key: 'system-email',
      label: t('admin.systemEmail'),
      children: (
        <AdminSystemEmail
          settings={systemEmail}
          loading={loading || actionLoading}
          onSave={(values) => runAction(() => api.saveAdminSystemEmail(values), '系统邮件配置已保存')}
          onTest={(to) => runAction(() => api.testAdminSystemEmail(to), '测试邮件请求已提交', false)}
        />
      )
    },
    {
      key: 'audit-logs',
      label: t('admin.auditLogs'),
      children: (
        <AdminAuditLogs
          logs={auditLogs}
          users={users}
          loading={loading}
          onSearch={searchAuditLogs}
        />
      )
    }
  ];

  return (
    <Space direction="vertical" size={20} className="full-width">
      <PageHeader
        title={t('admin.title')}
        extra={
          <Button icon={<ReloadOutlined />} loading={loading} onClick={() => loadAdminData()}>
            {t('common.refresh')}
          </Button>
        }
      />
      <SectionCard>
        <Tabs items={tabItems} />
      </SectionCard>
    </Space>
  );
}

function AdminUsers({
  users,
  loading,
  onApprove,
  onResendVerification,
  onPasswordReset,
  onTemporaryPassword,
  onUpdateUser
}: {
  users: AdminUser[];
  loading: boolean;
  onApprove: (user: AdminUser) => void;
  onResendVerification: (user: AdminUser) => void;
  onPasswordReset: (user: AdminUser) => void;
  onTemporaryPassword: (user: AdminUser, password: string) => void;
  onUpdateUser: (user: AdminUser, patch: { role?: UserRole; status?: UserStatus }) => void;
}) {
  const [tempUser, setTempUser] = useState<AdminUser | null>(null);
  const [form] = Form.useForm<{ password: string }>();

  const columns: ColumnsType<AdminUser> = [
    { title: 'ID', dataIndex: 'id', width: 80 },
    {
      title: '用户',
      render: (_, user) => (
        <Space direction="vertical" size={0}>
          <Typography.Text strong>{user.username}</Typography.Text>
          <Typography.Text type="secondary">{user.email}</Typography.Text>
        </Space>
      )
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 180,
      render: (_, user) => (
        <Select
          value={user.status}
          options={statusValues.map((value) => ({ value, label: adminUserStatusMeta(value).label }))}
          onChange={(status) => onUpdateUser(user, { status })}
          className="table-select"
        />
      )
    },
    {
      title: '角色',
      dataIndex: 'role',
      width: 140,
      render: (_, user) => (
        <Select
          value={user.role}
          options={roleValues.map((value) => ({ value, label: value }))}
          onChange={(role) => onUpdateUser(user, { role })}
          className="table-select"
        />
      )
    },
    {
      title: '资源',
      render: (_, user) => <ResourceCountTags counts={user.resourceCounts} />
    },
    {
      title: '创建时间',
      dataIndex: 'createdAt',
      width: 190,
      render: formatDate
    },
    {
      title: '操作',
      width: 380,
      render: (_, user) => (
        <Space wrap>
          <Button
            icon={<CheckCircleOutlined />}
            disabled={user.status !== 'pending_review'}
            onClick={() => onApprove(user)}
          >
            审批
          </Button>
          <Button
            icon={<MailOutlined />}
            disabled={user.status !== 'pending_email'}
            onClick={() => onResendVerification(user)}
          >
            重发验证
          </Button>
          <Button icon={<SendOutlined />} onClick={() => onPasswordReset(user)}>
            重置邮件
          </Button>
          <Button icon={<UserSwitchOutlined />} onClick={() => setTempUser(user)}>
            临时密码
          </Button>
        </Space>
      )
    }
  ];

  async function submitTemporaryPassword() {
    if (!tempUser) return;
    const values = await form.validateFields();
    onTemporaryPassword(tempUser, values.password);
    setTempUser(null);
    form.resetFields();
  }

  return (
    <>
      <Table
        rowKey="id"
        columns={columns}
        dataSource={users}
        loading={loading}
        scroll={{ x: 1100 }}
      />
      <Modal
        title={tempUser ? `设置临时密码 · ${tempUser.username}` : '设置临时密码'}
        open={Boolean(tempUser)}
        confirmLoading={loading}
        onCancel={() => setTempUser(null)}
        onOk={submitTemporaryPassword}
      >
        <Form form={form} layout="vertical">
          <Form.Item
            name="password"
            label="临时密码"
            rules={[{ required: true, min: 8, message: '密码至少需要 8 位。' }]}
          >
            <Input.Password autoComplete="new-password" />
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
}

function AdminResources({
  users,
  inventory,
  loading,
  onTransferDomain,
  onTransferDnsCredential,
  onTransferApiTokens
}: {
  users: AdminUser[];
  inventory: AdminResourceInventory | null;
  loading: boolean;
  onTransferDomain: (domainId: number, values: { targetUserId: number; dnsCredentialMode?: 'domain_only' | 'with_dns_credential' | 'clear_dns_credential' }) => Promise<void>;
  onTransferDnsCredential: (credentialId: number, values: { targetUserId: number }) => Promise<void>;
  onTransferApiTokens: (values: { tokenIds: number[]; targetUserId: number }) => Promise<void>;
}) {
  const [domainForm] = Form.useForm<{ domainId: number; targetUserId: number; dnsCredentialMode: 'domain_only' | 'with_dns_credential' | 'clear_dns_credential' }>();
  const [dnsForm] = Form.useForm<{ credentialId: number; targetUserId: number }>();
  const [tokenForm] = Form.useForm<{ tokenIds: number[]; targetUserId: number }>();
  const groups = inventory?.users || [];
  const targetOptions = users
    .filter((user) => user.status !== 'disabled')
    .map((user) => ({ value: user.id, label: `${user.username} (#${user.id})` }));
  const domains = groups.flatMap((group) => group.domains.map((domain) => ({ ...domain, owner: group.user })));
  const credentials = groups.flatMap((group) => group.dnsCredentials.map((credential) => ({ ...credential, owner: group.user })));
  const tokens = groups.flatMap((group) => group.apiTokens.map((token) => ({ ...token, owner: group.user })));

  const groupColumns: ColumnsType<AdminResourceInventory['users'][number]> = [
    {
      title: '用户',
      render: (_, group) => (
        <Space>
          <Typography.Text strong>{group.user.username}</Typography.Text>
          <UserStatusTag status={group.user.status} />
        </Space>
      )
    },
    { title: '资源', render: (_, group) => <ResourceCountTags counts={group.user.resourceCounts} /> },
    { title: '发送记录', dataIndex: 'sendEventCount', width: 120 },
    {
      title: 'SMTP',
      width: 120,
      render: (_, group) => (
        group.smtpCredential
          ? <StatusPill tone="success">已配置</StatusPill>
          : <StatusPill tone="neutral">无</StatusPill>
      )
    }
  ];

  async function submitDomainTransfer(values: { domainId: number; targetUserId: number; dnsCredentialMode: 'domain_only' | 'with_dns_credential' | 'clear_dns_credential' }) {
    Modal.confirm({
      title: '确认迁移该域名？',
      onOk: async () => {
        await onTransferDomain(values.domainId, {
          targetUserId: values.targetUserId,
          dnsCredentialMode: values.dnsCredentialMode
        });
        domainForm.resetFields();
      }
    });
  }

  async function submitDnsTransfer(values: { credentialId: number; targetUserId: number }) {
    Modal.confirm({
      title: '确认迁移该 DNS 凭据？',
      onOk: async () => {
        await onTransferDnsCredential(values.credentialId, { targetUserId: values.targetUserId });
        dnsForm.resetFields();
      }
    });
  }

  async function submitTokenTransfer(values: { tokenIds: number[]; targetUserId: number }) {
    Modal.confirm({
      title: `确认迁移 ${values.tokenIds.length} 个 API Token？`,
      onOk: async () => {
        await onTransferApiTokens({ tokenIds: values.tokenIds, targetUserId: values.targetUserId });
        tokenForm.resetFields();
      }
    });
  }

  return (
    <Space direction="vertical" size={16} className="full-width">
      {inventory?.warnings?.length ? (
        <Alert
          type="warning"
          showIcon
          message={`发现 ${inventory.warnings.length} 个 DNS 凭据归属不一致的域名`}
        />
      ) : null}
      <div className="form-grid three">
        <SectionCard title="迁移域名">
          <Form form={domainForm} layout="vertical" onFinish={submitDomainTransfer} disabled={loading}>
            <Form.Item name="domainId" label="域名" rules={[{ required: true }]}>
              <Select
                showSearch
                optionFilterProp="label"
                options={domains.map((domain) => ({
                  value: domain.id,
                  label: `${domain.domain} · ${domain.owner.username}`
                }))}
              />
            </Form.Item>
            <Form.Item name="targetUserId" label="目标用户" rules={[{ required: true }]}>
              <Select options={targetOptions} />
            </Form.Item>
            <Form.Item name="dnsCredentialMode" label="DNS 凭据" initialValue="domain_only">
              <Select
                options={[
                  { value: 'domain_only', label: '仅迁移域名' },
                  { value: 'with_dns_credential', label: '连同 DNS 凭据迁移' },
                  { value: 'clear_dns_credential', label: '清空 DNS 凭据绑定' }
                ]}
              />
            </Form.Item>
            <Button type="primary" htmlType="submit" loading={loading}>执行迁移</Button>
          </Form>
        </SectionCard>
        <SectionCard title="迁移 DNS 凭据">
          <Form form={dnsForm} layout="vertical" onFinish={submitDnsTransfer} disabled={loading}>
            <Form.Item name="credentialId" label="DNS 凭据" rules={[{ required: true }]}>
              <Select
                showSearch
                optionFilterProp="label"
                options={credentials.map((credential) => ({
                  value: credential.id,
                  label: `${credential.name} · ${credential.zoneName} · ${credential.owner.username}`
                }))}
              />
            </Form.Item>
            <Form.Item name="targetUserId" label="目标用户" rules={[{ required: true }]}>
              <Select options={targetOptions} />
            </Form.Item>
            <Button type="primary" htmlType="submit" loading={loading}>执行迁移</Button>
          </Form>
        </SectionCard>
        <SectionCard title="迁移 API Token">
          <Form form={tokenForm} layout="vertical" onFinish={submitTokenTransfer} disabled={loading}>
            <Form.Item name="tokenIds" label="API Token" rules={[{ required: true }]}>
              <Select
                mode="multiple"
                optionFilterProp="label"
                options={tokens.map((token) => ({
                  value: token.id,
                  label: `${token.name} · ${token.tokenPrefix} · ${token.owner.username}`
                }))}
              />
            </Form.Item>
            <Form.Item name="targetUserId" label="目标用户" rules={[{ required: true }]}>
              <Select options={targetOptions} />
            </Form.Item>
            <Button type="primary" htmlType="submit" loading={loading}>执行迁移</Button>
          </Form>
        </SectionCard>
      </div>
      <SectionCard title="资源归属">
        <Table
          rowKey={(group) => group.user.id}
          columns={groupColumns}
          dataSource={groups}
          loading={loading}
          expandable={{ expandedRowRender: renderResourceDetails }}
        />
      </SectionCard>
    </Space>
  );
}

function renderResourceDetails(group: AdminResourceInventory['users'][number]) {
  return (
    <Space direction="vertical" size={16} className="full-width">
      <Descriptions size="small" column={2}>
        <Descriptions.Item label="邮箱">{group.user.email}</Descriptions.Item>
        <Descriptions.Item label="角色">{group.user.role}</Descriptions.Item>
      </Descriptions>
      <Table
        size="small"
        rowKey="id"
        pagination={false}
        dataSource={group.domains}
        columns={[
          { title: '域名', dataIndex: 'domain' },
          { title: '发信主机', dataIndex: 'senderHost' },
          { title: 'DNS 凭据 ID', dataIndex: 'dnsCredentialId' }
        ]}
      />
      <Table
        size="small"
        rowKey="id"
        pagination={false}
        dataSource={group.dnsCredentials}
        columns={[
          { title: 'DNS 凭据', dataIndex: 'name' },
          { title: 'Provider', dataIndex: 'provider' },
          { title: 'Zone', dataIndex: 'zoneName' }
        ]}
      />
      <Table
        size="small"
        rowKey="id"
        pagination={false}
        dataSource={group.apiTokens}
        columns={[
          { title: 'API Token', dataIndex: 'name' },
          { title: '前缀', dataIndex: 'tokenPrefix' },
          { title: '创建时间', dataIndex: 'createdAt', render: formatDate }
        ]}
      />
    </Space>
  );
}

function AdminMigration({
  users,
  loading,
  onPreview,
  onExecute
}: {
  users: AdminUser[];
  loading: boolean;
  onPreview: (values: { sourceUserId: number; targetUserId: number }) => Promise<{ preview: UserMergePreview }>;
  onExecute: (values: {
    sourceUserId: number;
    targetUserId: number;
    options: Partial<UserMergeOptions>;
    confirmation: string;
  }) => Promise<void>;
}) {
  const { message } = AntApp.useApp();
  const [form] = Form.useForm<{ sourceUserId: number; targetUserId: number }>();
  const [preview, setPreview] = useState<UserMergePreview | null>(null);
  const [options, setOptions] = useState<Partial<UserMergeOptions>>({});
  const [confirmation, setConfirmation] = useState('');
  const userOptions = users.map((user) => ({ value: user.id, label: `${user.username} (#${user.id})` }));

  async function submitPreview(values: { sourceUserId: number; targetUserId: number }) {
    try {
      const result = await onPreview(values);
      setPreview(result.preview);
      setOptions(result.preview.defaultOptions);
      setConfirmation('');
    } catch (error) {
      message.error(error instanceof Error ? error.message : '预览失败');
    }
  }

  async function execute() {
    if (!preview) return;
    await onExecute({
      sourceUserId: preview.sourceUser.id,
      targetUserId: preview.targetUser.id,
      options,
      confirmation
    });
    setPreview(null);
    form.resetFields();
    setConfirmation('');
  }

  const expectedConfirmation = preview
    ? buildMergeConfirmationText(preview.sourceUser, preview.targetUser)
    : '';

  return (
    <Space direction="vertical" size={16} className="full-width">
      <SectionCard title="合并预览">
        <Form form={form} layout="inline" onFinish={submitPreview} disabled={loading}>
          <Form.Item name="sourceUserId" label="源用户" rules={[{ required: true }]}>
            <Select options={userOptions} className="toolbar-select" />
          </Form.Item>
          <Form.Item name="targetUserId" label="目标用户" rules={[{ required: true }]}>
            <Select options={userOptions} className="toolbar-select" />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={loading}>预览</Button>
        </Form>
      </SectionCard>
      {preview ? (
        <SectionCard title={`${preview.sourceUser.username} → ${preview.targetUser.username}`}>
          <Space direction="vertical" size={16} className="full-width">
            {preview.warnings.length ? (
              <Alert type="warning" showIcon message={preview.warnings.map((item) => item.message || item.type).join('；')} />
            ) : null}
            <Space wrap>
              {mergePreviewSummary(preview).map((item) => (
                <StatusPill key={item.key} tone="neutral">{item.label}: {item.count}</StatusPill>
              ))}
            </Space>
            <div className="form-grid two">
              {mergeOptionLabels.map(([key, label]) => (
                <Checkbox
                  key={key}
                  checked={options[key] !== false}
                  onChange={(event) => setOptions((current) => ({ ...current, [key]: event.target.checked }))}
                >
                  {label}
                </Checkbox>
              ))}
            </div>
            <Descriptions column={1} bordered size="small">
              <Descriptions.Item label="确认文本">
                <Typography.Text code>{expectedConfirmation}</Typography.Text>
              </Descriptions.Item>
            </Descriptions>
            <Input
              value={confirmation}
              onChange={(event) => setConfirmation(event.target.value)}
              placeholder={expectedConfirmation}
            />
            <Button
              danger
              type="primary"
              loading={loading}
              disabled={confirmation !== expectedConfirmation}
              onClick={execute}
            >
              执行合并
            </Button>
          </Space>
        </SectionCard>
      ) : (
        <EmptyState description="暂无预览" />
      )}
    </Space>
  );
}

function AdminSystemEmail({
  settings,
  loading,
  onSave,
  onTest
}: {
  settings: SystemEmailSettings | null;
  loading: boolean;
  onSave: (values: Partial<SystemEmailSettings>) => Promise<void>;
  onTest: (to?: string) => Promise<void>;
}) {
  const [form] = Form.useForm<SystemEmailSettings>();

  useEffect(() => {
    if (settings) form.setFieldsValue(settings);
  }, [form, settings]);

  async function submit(values: SystemEmailSettings) {
    await onSave(serializeSystemEmailPayload(values));
    form.setFieldValue('password', '');
  }

  return (
    <SectionCard title="系统邮件服务器">
      <Form form={form} layout="vertical" onFinish={submit} disabled={loading}>
        <div className="form-grid two">
          <Form.Item name="host" label="SMTP Host" rules={[{ required: true }]}>
            <Input />
          </Form.Item>
          <Form.Item name="port" label="SMTP Port" rules={[{ required: true }]}>
            <InputNumber min={1} max={65535} className="full-width" />
          </Form.Item>
          <Form.Item name="secure" label="SSL / TLS" valuePropName="checked">
            <Switch />
          </Form.Item>
          <Form.Item name="helo" label="HELO">
            <Input />
          </Form.Item>
          <Form.Item name="username" label="Username">
            <Input autoComplete="off" />
          </Form.Item>
          <Form.Item name="password" label={settings?.passwordSet ? 'Password（留空保留）' : 'Password'}>
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Form.Item name="fromEmail" label="From Email" rules={[{ required: true, type: 'email' }]}>
            <Input />
          </Form.Item>
          <Form.Item name="fromName" label="From Name">
            <Input />
          </Form.Item>
          <Form.Item name="testRecipient" label="Test Recipient">
            <Input />
          </Form.Item>
        </div>
        <Space wrap>
          <Button type="primary" htmlType="submit" loading={loading}>保存配置</Button>
          <Button onClick={() => onTest(form.getFieldValue('testRecipient'))} loading={loading}>发送测试</Button>
        </Space>
      </Form>
    </SectionCard>
  );
}

function AdminAuditLogs({
  logs,
  users,
  loading,
  onSearch
}: {
  logs: AuditLogEntry[];
  users: AdminUser[];
  loading: boolean;
  onSearch: (query: string) => Promise<void>;
}) {
  const [form] = Form.useForm();
  const userOptions = users.map((user) => ({ value: user.id, label: `${user.username} (#${user.id})` }));

  const columns: ColumnsType<AuditLogEntry> = [
    { title: '时间', dataIndex: 'createdAt', width: 190, render: formatDate },
    { title: '动作', dataIndex: 'action', width: 220 },
    { title: '操作者', dataIndex: 'actorUserId', width: 130, render: (value) => value ?? 'system' },
    { title: '目标用户', dataIndex: 'targetUserId', width: 130, render: (value) => value ?? '-' },
    { title: '目标', render: (_, log) => `${log.targetType}:${log.targetId || '-'}`, width: 180 },
    {
      title: '摘要',
      dataIndex: 'summary',
      render: (value) => (
        <Typography.Text code ellipsis>
          {JSON.stringify(value)}
        </Typography.Text>
      )
    }
  ];

  async function submit(values: Record<string, unknown>) {
    await onSearch(serializeAuditFilters(values));
  }

  return (
    <Space direction="vertical" size={16} className="full-width">
      <SectionCard className="admin-audit-toolbar-card">
        <Form form={form} layout="inline" onFinish={submit} disabled={loading}>
          <Form.Item name="actorUserId" label="操作者">
            <Select allowClear options={[{ value: 'system', label: 'system' }, ...userOptions]} className="toolbar-select" />
          </Form.Item>
          <Form.Item name="targetUserId" label="目标用户">
            <Select allowClear options={userOptions} className="toolbar-select" />
          </Form.Item>
          <Form.Item name="action" label="动作">
            <Input placeholder="admin.user_merge" />
          </Form.Item>
          <Form.Item name="from" label="开始">
            <Input placeholder="2026-07-08" />
          </Form.Item>
          <Form.Item name="to" label="结束">
            <Input placeholder="2026-07-09" />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={loading}>查询</Button>
        </Form>
      </SectionCard>
      <Table rowKey="id" columns={columns} dataSource={logs} loading={loading} scroll={{ x: 1100 }} />
    </Space>
  );
}

function ResourceCountTags({ counts }: { counts?: AdminUser['resourceCounts'] }) {
  if (!counts) return <Tag>无资源</Tag>;
  return (
    <Space wrap>
      <Tag>域名 {counts.domains}</Tag>
      <Tag>DNS {counts.dnsCredentials}</Tag>
      <Tag>Token {counts.apiTokens}</Tag>
      <Tag>记录 {counts.sendEvents}</Tag>
      <Tag>SMTP {counts.smtpCredential}</Tag>
    </Space>
  );
}

function UserStatusTag({ status }: { status: UserStatus }) {
  const meta = adminUserStatusMeta(status);
  const tone = statusToneFromColor(meta.color);
  return <StatusPill tone={tone}>{meta.label}</StatusPill>;
}

function statusToneFromColor(color: string): 'success' | 'warning' | 'error' | 'info' | 'neutral' {
  if (color === 'green' || color === 'success') return 'success';
  if (color === 'gold' || color === 'orange' || color === 'warning') return 'warning';
  if (color === 'red' || color === 'error' || color === 'volcano') return 'error';
  if (color === 'blue' || color === 'processing' || color === 'cyan') return 'info';
  return 'neutral';
}

function formatDate(value?: string) {
  return value ? new Date(value).toLocaleString() : '-';
}
