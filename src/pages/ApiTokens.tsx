import { CopyOutlined, DeleteOutlined, EditOutlined, KeyOutlined } from '@ant-design/icons';
import { Alert, Button, Checkbox, Collapse, Descriptions, Form, Input, Modal, Popconfirm, Space, Table, Tag, Tooltip, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { useState } from 'react';

import { CodeBlock } from '../components/common/CodeBlock';
import { PageHeader } from '../components/common/PageHeader';
import { SectionCard } from '../components/common/SectionCard';
import { StatusPill, type StatusTone } from '../components/common/StatusPill';
import {
  buildApiUsageExamples,
  buildMailboxApiUsageExamples,
  canCopyFullApiToken,
  formatApiTokenPrefix,
  getCreatedApiTokenSecret
} from '../frontend/api-token-model.js';
import { useI18n } from '../frontend/i18n/react';
import type { ApiToken, RuntimeConfig } from '../frontend/types';

interface TokenFormValues {
  name: string;
  scopes: string[];
  expiresAt?: string;
}

interface ApiTokensProps {
  tokens: ApiToken[];
  config: RuntimeConfig | null;
  loading?: boolean;
  onCreate: (values: { name: string; scopes: string[]; expiresAt?: string | null }) => Promise<ApiToken | null | void>;
  onUpdate: (token: ApiToken, values: { name: string; scopes: string[]; expiresAt?: string | null }) => Promise<void>;
  onRevoke: (token: ApiToken) => Promise<void>;
  onCopy: (value: string) => void;
}

const scopeOptions = [
  { label: 'send', value: 'send' },
  { label: 'mailboxes:read', value: 'mailboxes:read' },
  { label: 'mailboxes:write', value: 'mailboxes:write' }
];

export default function ApiTokens({ tokens, config, loading, onCreate, onUpdate, onRevoke, onCopy }: ApiTokensProps) {
  const { t } = useI18n();
  const [form] = Form.useForm<TokenFormValues>();
  const [editForm] = Form.useForm<TokenFormValues>();
  const [createdToken, setCreatedToken] = useState<ApiToken | null>(null);
  const [editingToken, setEditingToken] = useState<ApiToken | null>(null);
  const endpoint = `${config?.appBaseUrl || window.location.origin}/api/send`;
  const mailboxEndpoint = `${config?.appBaseUrl || window.location.origin}/api/mailboxes`;
  const examples = buildApiUsageExamples({
    endpoint,
    token: '<USER_API_TOKEN>',
    from: 'noreply@example.com',
    to: 'user@example.com'
  });
  const mailboxExamples = buildMailboxApiUsageExamples({
    endpoint: mailboxEndpoint,
    token: '<MAILBOX_API_TOKEN>'
  });

  const columns: ColumnsType<ApiToken> = [
    { title: t('tokens.name'), dataIndex: 'name', width: 190 },
    {
      title: t('tokens.prefix'),
      dataIndex: 'tokenPrefix',
      width: 168,
      render: (_value, token) => <Typography.Text code>{formatApiTokenPrefix(token)}</Typography.Text>
    },
    {
      title: t('tokens.scopes'),
      dataIndex: 'scopes',
      width: 260,
      render: (scopes: string[]) => (
        <Space size={[4, 4]} wrap>
          {(scopes || []).map((scope) => <Tag key={scope}>{scope}</Tag>)}
        </Space>
      )
    },
    {
      title: t('tokens.status'),
      dataIndex: 'status',
      width: 104,
      render: (_value, token) => <StatusPill tone={tokenStatusTone(token.status)}>{tokenStatusText(token.status, t)}</StatusPill>
    },
    { title: t('tokens.expiresAt'), dataIndex: 'expiresAt', width: 176, render: formatOptionalTime },
    { title: t('tokens.lastUsed'), dataIndex: 'lastUsedAt', width: 176, render: (value) => value ? formatOptionalTime(value) : t('tokens.neverUsed') },
    {
      title: t('tokens.actions'),
      fixed: 'right',
      width: 142,
      render: (_value, token) => (
        <Space size={4}>
          <Tooltip title={t('tokens.copyPrefix')}>
            <Button aria-label={t('tokens.copyPrefix')} icon={<CopyOutlined />} onClick={() => onCopy(token.tokenPrefix)} />
          </Tooltip>
          <Tooltip title={t('tokens.edit')}>
            <Button
              aria-label={t('tokens.edit')}
              disabled={token.status === 'revoked'}
              icon={<EditOutlined />}
              onClick={() => openEdit(token)}
            />
          </Tooltip>
          <Popconfirm title={t('tokens.revokeConfirm')} onConfirm={() => void onRevoke(token)} disabled={token.status === 'revoked'}>
            <Button aria-label={t('tokens.revoke')} danger disabled={token.status === 'revoked'} icon={<DeleteOutlined />} />
          </Popconfirm>
        </Space>
      )
    }
  ];

  async function submit(values: TokenFormValues) {
    const token = await onCreate(toTokenPayload(values));
    if (token && canCopyFullApiToken(token)) setCreatedToken(token);
    form.resetFields();
    form.setFieldsValue({ scopes: ['send'] });
  }

  function openEdit(token: ApiToken) {
    setEditingToken(token);
    editForm.setFieldsValue({
      name: token.name,
      scopes: token.scopes || ['send'],
      expiresAt: toDatetimeLocal(token.expiresAt)
    });
  }

  async function saveEdit() {
    if (!editingToken) return;
    const values = await editForm.validateFields();
    await onUpdate(editingToken, toTokenPayload(values));
    setEditingToken(null);
  }

  return (
    <>
      <Space direction="vertical" size={20} className="full-width">
        <PageHeader title={t('nav.tokens')} subtitle={t('tokens.subtitle')} />

        <SectionCard title={t('tokens.createTitle')}>
          <Form form={form} layout="vertical" initialValues={{ scopes: ['send'] }} onFinish={submit}>
            <div className="token-form-grid">
              <Form.Item name="name" label={t('tokens.name')} rules={[{ required: true, message: t('tokens.nameRequired') }]}>
                <Input placeholder={t('tokens.namePlaceholder')} autoComplete="off" />
              </Form.Item>
              <Form.Item name="expiresAt" label={t('tokens.expiresAt')} extra={t('tokens.expiresAtExtra')}>
                <Input type="datetime-local" />
              </Form.Item>
            </div>
            <Form.Item name="scopes" label={t('tokens.scopes')} rules={[{ required: true, type: 'array', min: 1, message: t('tokens.scopesRequired') }]} extra={t('tokens.scopesExtra')}>
              <Checkbox.Group options={scopeOptions} />
            </Form.Item>
            <Button type="primary" htmlType="submit" loading={loading} icon={<KeyOutlined />}>
              {t('tokens.create')}
            </Button>
          </Form>
        </SectionCard>

        <SectionCard title={t('tokens.listTitle')} extra={<StatusPill tone="neutral">{tokens.length}</StatusPill>}>
          <Alert type="info" showIcon message={t('tokens.prefixOnlyHelp')} className="token-list-alert" />
          <Table rowKey="id" columns={columns} dataSource={tokens} scroll={{ x: 1260 }} />
        </SectionCard>

        <SectionCard title={t('tokens.docsTitle')}>
          <Space direction="vertical" size={16} className="full-width">
            <Alert type="info" showIcon message={t('tokens.noTokenHint')} />
            <Descriptions column={1} bordered size="small">
              <Descriptions.Item label={t('tokens.endpoint')}>{copyable(endpoint, onCopy)}</Descriptions.Item>
              <Descriptions.Item label={t('tokens.mailboxEndpoint')}>{copyable(mailboxEndpoint, onCopy)}</Descriptions.Item>
              <Descriptions.Item label={t('tokens.authHeader')}>{copyable(t('tokens.authHeaderValue'), onCopy)}</Descriptions.Item>
              <Descriptions.Item label={t('tokens.contentType')}><Typography.Text code>application/json</Typography.Text></Descriptions.Item>
            </Descriptions>
            <Collapse
              defaultActiveKey={['send']}
              items={[
                {
                  key: 'send',
                  label: t('tokens.sendApi'),
                  children: <ApiExamples examples={examples} onCopy={onCopy} labels={{ curl: t('tokens.curlExample'), request: t('tokens.requestExample'), response: t('tokens.responseExample') }} />
                },
                {
                  key: 'mailboxes',
                  label: t('tokens.mailboxApi'),
                  children: (
                    <Space direction="vertical" size={12} className="full-width">
                      <Alert type="info" showIcon message={t('tokens.mailboxApiHint')} />
                      <Typography.Text strong>{t('tokens.permanentMailbox')}</Typography.Text>
                      <CodeBlock value={mailboxExamples.permanentCurl} onCopy={onCopy} />
                      <Typography.Text strong>{t('tokens.temporaryMailbox')}</Typography.Text>
                      <CodeBlock value={mailboxExamples.temporaryCurl} onCopy={onCopy} />
                      <Typography.Text strong>{t('tokens.mailboxResponse')}</Typography.Text>
                      <CodeBlock value={mailboxExamples.successResponse} onCopy={onCopy} />
                    </Space>
                  )
                }
              ]}
            />
            <Typography.Title level={5} className="api-doc-subheading">{t('tokens.securityTips')}</Typography.Title>
            <ul className="api-doc-list">
              <li>{t('tokens.securityTipStore')}</li>
              <li>{t('tokens.securityTipRotate')}</li>
              <li>{t('tokens.securityTipScopes')}</li>
              <li>{t('tokens.securityTipDomain')}</li>
            </ul>
          </Space>
        </SectionCard>
      </Space>

      <Modal
        title={t('tokens.createdTitle')}
        open={Boolean(createdToken)}
        onCancel={() => setCreatedToken(null)}
        footer={[
          <Button key="close" onClick={() => setCreatedToken(null)}>{t('common.cancel')}</Button>,
          <Button key="copy" type="primary" icon={<CopyOutlined />} onClick={() => {
            const secret = getCreatedApiTokenSecret(createdToken || {});
            if (secret) onCopy(secret);
          }}>{t('tokens.copyCreated')}</Button>
        ]}
      >
        <Space direction="vertical" size={16} className="full-width">
          <Alert type="error" showIcon message={t('tokens.createdWarning')} className="token-secret-alert" />
          <CodeBlock value={getCreatedApiTokenSecret(createdToken || {}) || ''} onCopy={onCopy} />
        </Space>
      </Modal>

      <Modal
        title={t('tokens.editTitle')}
        open={Boolean(editingToken)}
        confirmLoading={loading}
        onCancel={() => setEditingToken(null)}
        onOk={() => void saveEdit()}
      >
        <Form form={editForm} layout="vertical">
          <Form.Item name="name" label={t('tokens.name')} rules={[{ required: true, message: t('tokens.nameRequired') }]}>
            <Input autoComplete="off" />
          </Form.Item>
          <Form.Item name="expiresAt" label={t('tokens.expiresAt')} extra={t('tokens.expiresAtExtra')}>
            <Input type="datetime-local" />
          </Form.Item>
          <Form.Item name="scopes" label={t('tokens.scopes')} rules={[{ required: true, type: 'array', min: 1, message: t('tokens.scopesRequired') }]}>
            <Checkbox.Group options={scopeOptions} />
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
}

function ApiExamples({ examples, onCopy, labels }: {
  examples: ReturnType<typeof buildApiUsageExamples>;
  onCopy: (value: string) => void;
  labels: { curl: string; request: string; response: string };
}) {
  return (
    <Space direction="vertical" size={12} className="full-width">
      <Typography.Text strong>{labels.curl}</Typography.Text>
      <CodeBlock value={examples.curl} onCopy={onCopy} />
      <Typography.Text strong>{labels.request}</Typography.Text>
      <CodeBlock value={examples.requestBody} onCopy={onCopy} />
      <Typography.Text strong>{labels.response}</Typography.Text>
      <CodeBlock value={examples.successResponse} onCopy={onCopy} />
    </Space>
  );
}

function toTokenPayload(values: TokenFormValues) {
  return {
    name: values.name,
    scopes: values.scopes,
    expiresAt: values.expiresAt ? new Date(values.expiresAt).toISOString() : null
  };
}

function toDatetimeLocal(value?: string | null) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  const offset = date.getTimezoneOffset() * 60_000;
  return new Date(date.getTime() - offset).toISOString().slice(0, 16);
}

function tokenStatusTone(status?: string): StatusTone {
  if (status === 'active') return 'success';
  if (status === 'expired') return 'warning';
  if (status === 'revoked') return 'error';
  return 'neutral';
}

function tokenStatusText(status: string | undefined, t: (key: string) => string) {
  if (status === 'active') return t('tokens.statusActive');
  if (status === 'expired') return t('tokens.statusExpired');
  if (status === 'revoked') return t('tokens.statusRevoked');
  return '-';
}

function formatOptionalTime(value?: string | null) {
  return value ? new Date(value).toLocaleString() : '-';
}

function copyable(value: string, onCopy: (value: string) => void) {
  return (
    <Space>
      <Typography.Text code className="inline-code-value">{value}</Typography.Text>
      <Button aria-label="Copy" size="small" icon={<CopyOutlined />} onClick={() => onCopy(value)} />
    </Space>
  );
}
