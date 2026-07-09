import { CopyOutlined, DeleteOutlined, EditOutlined, PlusOutlined, ReloadOutlined } from '@ant-design/icons';
import { Button, Descriptions, Form, Input, InputNumber, Modal, Popconfirm, Space, Switch, Table, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { useState } from 'react';

import { PageHeader } from '../components/common/PageHeader';
import { SectionCard } from '../components/common/SectionCard';
import { StatusPill } from '../components/common/StatusPill';
import { useI18n } from '../frontend/i18n/react';
import type { RuntimeConfig, SmtpCredential, SmtpRelay, SmtpRelayPayload } from '../frontend/types';

interface SmtpCredentialsProps {
  config: RuntimeConfig | null;
  credential: SmtpCredential | null;
  credentials: SmtpCredential[];
  relays: SmtpRelay[];
  loading?: boolean;
  onCopy: (value: string) => void;
  onLoadCredential: (id: number) => Promise<SmtpCredential | null>;
  onSaveCredential: (values: { username: string; password?: string }, id?: number) => Promise<SmtpCredential | null>;
  onDeleteCredential: (credential: SmtpCredential) => Promise<void>;
  onLoadRelay: (id: number) => Promise<SmtpRelay | null>;
  onSaveRelay: (values: SmtpRelayPayload, id?: number) => Promise<SmtpRelay | null>;
  onDeleteRelay: (relay: SmtpRelay) => Promise<void>;
}

interface CredentialFormValues {
  username: string;
  password?: string;
}

export default function SmtpCredentials({
  config,
  credential,
  credentials,
  relays,
  loading,
  onCopy,
  onLoadCredential,
  onSaveCredential,
  onDeleteCredential,
  onLoadRelay,
  onSaveRelay,
  onDeleteRelay
}: SmtpCredentialsProps) {
  const { t } = useI18n();
  const [credentialForm] = Form.useForm<CredentialFormValues>();
  const [relayForm] = Form.useForm<SmtpRelayPayload>();
  const [credentialOpen, setCredentialOpen] = useState(false);
  const [credentialLoading, setCredentialLoading] = useState(false);
  const [editingCredential, setEditingCredential] = useState<SmtpCredential | null>(null);
  const [relayOpen, setRelayOpen] = useState(false);
  const [relayLoading, setRelayLoading] = useState(false);
  const [editingRelay, setEditingRelay] = useState<SmtpRelay | null>(null);

  function generateCredentialPassword() {
    credentialForm.setFieldValue('password', randomPassword());
  }

  function generateRelayPassword() {
    relayForm.setFieldValue('password', randomPassword());
  }

  function openCreateCredential() {
    setEditingCredential(null);
    credentialForm.setFieldsValue({
      username: credentials.length === 0 ? credential?.username || config?.submission?.username || '' : '',
      password: ''
    });
    setCredentialOpen(true);
  }

  async function openEditCredential(item: SmtpCredential) {
    if (!item.id) return;
    setEditingCredential(item);
    setCredentialOpen(true);
    setCredentialLoading(true);
    try {
      const detail = await onLoadCredential(item.id);
      if (!detail) {
        setCredentialOpen(false);
        return;
      }
      credentialForm.setFieldsValue({
        username: detail.username,
        password: detail.password || ''
      });
    } finally {
      setCredentialLoading(false);
    }
  }

  async function saveCredential() {
    const values = await credentialForm.validateFields();
    setCredentialLoading(true);
    try {
      const saved = await onSaveCredential(values, editingCredential?.id);
      if (!saved) return;
      setCredentialOpen(false);
      credentialForm.resetFields();
    } finally {
      setCredentialLoading(false);
    }
  }

  function closeCredentialModal() {
    setCredentialOpen(false);
    setEditingCredential(null);
    credentialForm.resetFields();
  }

  function openCreateRelay() {
    setEditingRelay(null);
    relayForm.setFieldsValue({
      name: '',
      host: '',
      port: 587,
      secure: false,
      username: '',
      password: '',
      helo: '',
      isDefault: relays.length === 0
    });
    setRelayOpen(true);
  }

  async function openEditRelay(relay: SmtpRelay) {
    setEditingRelay(relay);
    setRelayOpen(true);
    setRelayLoading(true);
    try {
      const detail = await onLoadRelay(relay.id);
      if (!detail) {
        setRelayOpen(false);
        return;
      }
      relayForm.setFieldsValue({
        name: detail.name,
        host: detail.host,
        port: detail.port,
        secure: detail.secure,
        username: detail.username,
        password: detail.password || '',
        helo: detail.helo,
        isDefault: detail.isDefault
      });
    } finally {
      setRelayLoading(false);
    }
  }

  async function saveRelay() {
    const values = await relayForm.validateFields();
    setRelayLoading(true);
    try {
      const saved = await onSaveRelay(values, editingRelay?.id);
      if (!saved) return;
      setRelayOpen(false);
      relayForm.resetFields();
    } finally {
      setRelayLoading(false);
    }
  }

  const credentialColumns: ColumnsType<SmtpCredential> = [
    {
      title: t('smtp.username'),
      dataIndex: 'username',
      width: 240,
      render: (value: string) => copyable(value, onCopy)
    },
    {
      title: t('smtp.password'),
      dataIndex: 'password',
      width: 280,
      render: (value: string | undefined) => (
        value
          ? copyable(value, onCopy)
          : <Typography.Text type="secondary">{t('smtp.passwordUnavailable')}</Typography.Text>
      )
    },
    {
      title: t('common.status'),
      dataIndex: 'passwordSet',
      width: 120,
      render: (value: boolean) => (
        <StatusPill tone={value ? 'success' : 'neutral'}>
          {value ? t('smtp.passwordSet') : t('smtp.passwordEmpty')}
        </StatusPill>
      )
    },
    {
      title: t('tokens.createdAt'),
      dataIndex: 'createdAt',
      width: 190,
      render: formatDate
    },
    {
      title: t('domains.actions'),
      fixed: 'right',
      width: 150,
      render: (_, item) => (
        <Space>
          <Button icon={<EditOutlined />} onClick={() => openEditCredential(item)} disabled={!item.id} />
          <Popconfirm title={t('smtp.deleteConfirm')} onConfirm={() => onDeleteCredential(item)} disabled={!item.id}>
            <Button danger icon={<DeleteOutlined />} disabled={!item.id} />
          </Popconfirm>
        </Space>
      )
    }
  ];

  const relayColumns: ColumnsType<SmtpRelay> = [
    {
      title: t('smtpRelay.name'),
      dataIndex: 'name',
      width: 190,
      render: (value, relay) => (
        <Space wrap>
          <Typography.Text strong>{value}</Typography.Text>
          {relay.isDefault ? <StatusPill tone="success">{t('smtpRelay.default')}</StatusPill> : null}
        </Space>
      )
    },
    {
      title: t('smtpRelay.server'),
      width: 220,
      render: (_, relay) => (
        <Space direction="vertical" size={0}>
          <Typography.Text code>{relay.host}:{relay.port}</Typography.Text>
          <Typography.Text type="secondary">{relay.secure ? 'SSL/TLS' : 'STARTTLS / Plain'}</Typography.Text>
        </Space>
      )
    },
    { title: t('smtpRelay.username'), dataIndex: 'username', width: 180, render: (value) => value || '-' },
    {
      title: t('smtpRelay.password'),
      dataIndex: 'passwordSet',
      width: 120,
      render: (value: boolean) => (
        <StatusPill tone={value ? 'success' : 'neutral'}>
          {value ? t('smtpRelay.passwordSet') : t('smtpRelay.passwordEmpty')}
        </StatusPill>
      )
    },
    { title: 'HELO', dataIndex: 'helo', width: 180, render: (value) => value || '-' },
    {
      title: t('domains.actions'),
      fixed: 'right',
      width: 150,
      render: (_, relay) => (
        <Space>
          <Button icon={<EditOutlined />} onClick={() => openEditRelay(relay)} />
          <Popconfirm title={t('smtpRelay.deleteConfirm')} onConfirm={() => onDeleteRelay(relay)}>
            <Button danger icon={<DeleteOutlined />} />
          </Popconfirm>
        </Space>
      )
    }
  ];

  return (
    <Space direction="vertical" size={20} className="full-width">
      <PageHeader title={t('nav.smtp')} />

      <SectionCard title={t('smtp.connectionTitle')}>
        <Descriptions column={1}>
          <Descriptions.Item label="SMTP Host">{copyable(config?.submission?.host || '-', onCopy)}</Descriptions.Item>
          <Descriptions.Item label="SMTP Port">
            <Space wrap size={8}>
              {(config?.submission?.ports || []).map((item) => (
                <StatusPill key={item.port} tone="info">
                  {item.port} · {item.protocol}
                </StatusPill>
              ))}
            </Space>
          </Descriptions.Item>
          <Descriptions.Item label="TLS / SSL">{config?.submission?.tls ? 'TLS' : 'STARTTLS'}</Descriptions.Item>
          <Descriptions.Item label={t('smtp.username')}>{copyable(credential?.username || config?.submission?.username || '-', onCopy)}</Descriptions.Item>
          <Descriptions.Item label={t('smtp.password')}>
            {credential?.password ? copyable(credential.password, onCopy) : <Typography.Text type="secondary">{t('smtp.resetToCopy')}</Typography.Text>}
          </Descriptions.Item>
        </Descriptions>
      </SectionCard>

      <SectionCard
        title={t('smtp.loginCredentialsTitle')}
        extra={
          <Button type="primary" icon={<PlusOutlined />} onClick={openCreateCredential}>
            {t('smtp.create')}
          </Button>
        }
      >
        <Table
          rowKey={(item) => item.id || item.username}
          columns={credentialColumns}
          dataSource={credentials}
          scroll={{ x: 980 }}
          pagination={credentials.length > 10 ? { pageSize: 10 } : false}
        />
      </SectionCard>

      <SectionCard
        title={t('smtpRelay.title')}
        extra={
          <Button type="primary" icon={<PlusOutlined />} onClick={openCreateRelay}>
            {t('smtpRelay.create')}
          </Button>
        }
      >
        <Table
          rowKey="id"
          columns={relayColumns}
          dataSource={relays}
          scroll={{ x: 1040 }}
          pagination={false}
        />
      </SectionCard>

      <Modal
        title={editingCredential ? t('smtp.editTitle') : t('smtp.createTitle')}
        open={credentialOpen}
        confirmLoading={loading || credentialLoading}
        onCancel={closeCredentialModal}
        onOk={saveCredential}
        width={560}
        destroyOnHidden
      >
        <Form form={credentialForm} layout="vertical">
          <Form.Item name="username" label={t('smtp.username')} rules={[{ required: true, message: t('smtp.usernameRequired') }]}>
            <Input autoComplete="off" />
          </Form.Item>
          <Form.Item
            name="password"
            label={t('smtp.password')}
            extra={editingCredential ? t('smtp.passwordExtra') : undefined}
            rules={[{ required: !editingCredential, message: t('smtp.passwordRequired') }]}
          >
            <Input autoComplete="new-password" />
          </Form.Item>
          <Form.Item>
            <Button icon={<ReloadOutlined />} onClick={generateCredentialPassword}>
              {t('smtp.regenerate')}
            </Button>
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title={editingRelay ? t('smtpRelay.editTitle') : t('smtpRelay.createTitle')}
        open={relayOpen}
        confirmLoading={loading || relayLoading}
        onCancel={() => setRelayOpen(false)}
        onOk={saveRelay}
        width={640}
        destroyOnHidden
      >
        <Form form={relayForm} layout="vertical">
          <Form.Item name="name" label={t('smtpRelay.name')} rules={[{ required: true, message: t('smtpRelay.nameRequired') }]}>
            <Input autoComplete="off" placeholder="Amazon SES" />
          </Form.Item>
          <Form.Item name="host" label="SMTP Host" rules={[{ required: true, message: t('smtpRelay.hostRequired') }]}>
            <Input autoComplete="off" placeholder="email-smtp.us-east-1.amazonaws.com" />
          </Form.Item>
          <Form.Item name="port" label="SMTP Port" rules={[{ required: true, message: t('smtpRelay.portRequired') }]}>
            <InputNumber min={1} max={65535} className="full-width" />
          </Form.Item>
          <Form.Item name="secure" label="SSL/TLS" valuePropName="checked">
            <Switch />
          </Form.Item>
          <Form.Item name="username" label={t('smtpRelay.username')}>
            <Input autoComplete="off" />
          </Form.Item>
          <Form.Item name="password" label={t('smtpRelay.password')} extra={t('smtpRelay.passwordExtra')}>
            <Input autoComplete="new-password" />
          </Form.Item>
          <Form.Item>
            <Button icon={<ReloadOutlined />} onClick={generateRelayPassword}>
              {t('smtpRelay.generatePassword')}
            </Button>
          </Form.Item>
          <Form.Item name="helo" label="HELO" extra={t('smtpRelay.heloExtra')}>
            <Input autoComplete="off" placeholder={config?.mailHostname || 'mail.example.com'} />
          </Form.Item>
          <Form.Item name="isDefault" label={t('smtpRelay.default')} valuePropName="checked">
            <Switch />
          </Form.Item>
        </Form>
      </Modal>
    </Space>
  );
}

function randomPassword() {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes)).replace(/[+/=]/g, '').slice(0, 28);
}

function copyable(value: string, onCopy: (value: string) => void) {
  return (
    <Space>
      <Typography.Text code className="inline-code-value">{value}</Typography.Text>
      <Button size="small" icon={<CopyOutlined />} onClick={() => onCopy(value)} />
    </Space>
  );
}

function formatDate(value?: string) {
  return value ? new Date(value).toLocaleString() : '-';
}
