import {
  CopyOutlined,
  KeyOutlined,
  InboxOutlined,
  PlusOutlined,
  ReloadOutlined,
  SearchOutlined,
  SettingOutlined,
  ThunderboltOutlined
} from '@ant-design/icons';
import {
  Alert,
  Button,
  Checkbox,
  Collapse,
  Descriptions,
  Drawer,
  Form,
  Input,
  InputNumber,
  Modal,
  Select,
  Space,
  Spin,
  Table,
  Tabs,
  Tag,
  Typography
} from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { useMemo, useState } from 'react';

import { EmptyState } from '../components/common/EmptyState';
import { PageHeader } from '../components/common/PageHeader';
import { SectionCard } from '../components/common/SectionCard';
import { StatusPill } from '../components/common/StatusPill';
import { useI18n } from '../frontend/i18n/react';
import type { Domain, DomainPatchPayload, InboundMailbox, InboundMessage, MailboxClientConfig, RuntimeConfig } from '../frontend/types';
import Webhooks from './Webhooks';

interface InboxProps {
  config: RuntimeConfig | null;
  domains: Domain[];
  mailboxes: InboundMailbox[];
  messages: InboundMessage[];
  loading?: boolean;
  onCreateMailbox: (values: {
    address: string;
    displayName?: string;
    password: string;
    aliases?: string;
    forwardTo?: string;
    keepForwarded?: boolean;
    quotaMb?: number | string | null;
  }) => Promise<{ mailbox: InboundMailbox; clientConfig?: MailboxClientConfig } | null>;
  onPatchDomain: (domain: Domain, values: DomainPatchPayload) => Promise<void>;
  onLoadMessages: (mailboxId?: number | null) => Promise<InboundMessage[]>;
  onLoadMessage: (id: number) => Promise<InboundMessage | null>;
  onCopy: (value: string) => void;
  onAddDomain: () => void;
}

interface MailboxFormValues {
  localPart: string;
  domain: string;
  password: string;
  displayName?: string;
  quotaMb?: number | null;
  aliases?: string;
  forwardTo?: string;
  keepForwarded?: boolean;
}

interface CatchAllFormValues {
  catchAllAddress?: string;
}

export default function Inbox({
  config,
  domains,
  mailboxes,
  messages,
  loading,
  onCreateMailbox,
  onPatchDomain,
  onLoadMessages,
  onLoadMessage,
  onCopy,
  onAddDomain
}: InboxProps) {
  const { t } = useI18n();
  const [form] = Form.useForm<MailboxFormValues>();
  const [catchAllForm] = Form.useForm<CatchAllFormValues>();
  const [mailboxOpen, setMailboxOpen] = useState(false);
  const [mailboxLoading, setMailboxLoading] = useState(false);
  const [clientConfig, setClientConfig] = useState<MailboxClientConfig | null>(null);
  const [webhookMailbox, setWebhookMailbox] = useState<InboundMailbox | null>(null);
  const [catchAllDomain, setCatchAllDomain] = useState<Domain | null>(null);
  const [catchAllLoading, setCatchAllLoading] = useState(false);
  const [selectedMailboxId, setSelectedMailboxId] = useState<number | null>(null);
  const [query, setQuery] = useState('');
  const [selectedMessage, setSelectedMessage] = useState<InboundMessage | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState('');

  const filteredMessages = useMemo(() => {
    const cleanQuery = query.trim().toLowerCase();
    if (!cleanQuery) return messages;
    return messages.filter((message) => [
      message.sender,
      message.mailboxAddress,
      message.subject,
      message.preview,
      message.recipients.join(', ')
    ].some((value) => String(value || '').toLowerCase().includes(cleanQuery)));
  }, [messages, query]);

  const domainMailboxCounts = useMemo(() => {
    const counts = new Map<number, number>();
    for (const mailbox of mailboxes) counts.set(mailbox.domainId, (counts.get(mailbox.domainId) || 0) + 1);
    return counts;
  }, [mailboxes]);

  const domainColumns: ColumnsType<Domain> = [
    {
      title: t('domains.domain'),
      dataIndex: 'domain',
      render: (value: string, domain) => (
        <Space wrap>
          <Typography.Text strong>{value}</Typography.Text>
          <Typography.Text type="secondary">{domainMailboxCounts.get(domain.id) || 0} {t('inbox.mailboxUnit')}</Typography.Text>
        </Space>
      )
    },
    {
      title: t('inbox.catchAllAddress'),
      dataIndex: 'catchAllAddress',
      render: (value: string) => value ? <Tag color={value === '/dev/null' ? 'default' : 'blue'}>{value}</Tag> : <Tag>{t('inbox.catchAllDisabled')}</Tag>
    },
    {
      title: t('common.actions'),
      width: 130,
      render: (_value, domain) => (
        <Button icon={<SettingOutlined />} onClick={() => openCatchAllModal(domain)}>
          {t('common.edit')}
        </Button>
      )
    }
  ];

  const mailboxColumns: ColumnsType<InboundMailbox> = [
    {
      title: t('inbox.mailboxAddress'),
      dataIndex: 'address',
      render: (value: string, mailbox) => (
        <Space wrap>
          <Typography.Text strong>{value}</Typography.Text>
          {mailbox.displayName ? <Typography.Text type="secondary">{mailbox.displayName}</Typography.Text> : null}
        </Space>
      )
    },
    {
      title: t('inbox.forwardTo'),
      dataIndex: 'forwardTo',
      width: 240,
      render: (value: string[], mailbox) => value?.length ? (
        <Space direction="vertical" size={2}>
          <Typography.Text ellipsis>{value.join(', ')}</Typography.Text>
          <Tag color={mailbox.keepForwarded ? 'blue' : 'orange'}>
            {mailbox.keepForwarded ? t('inbox.keepForwarded') : t('inbox.forwardOnly')}
          </Tag>
        </Space>
      ) : '-'
    },
    {
      title: t('inbox.quotaMb'),
      dataIndex: 'quotaMb',
      width: 120,
      render: (value: number | null) => value === null ? t('inbox.unlimited') : `${value} MB`
    },
    {
      title: t('inbox.unread'),
      dataIndex: 'unreadCount',
      width: 100,
      render: (value: number) => (
        <StatusPill tone={value > 0 ? 'warning' : 'neutral'}>{String(value)}</StatusPill>
      )
    },
    { title: t('inbox.messageCount'), dataIndex: 'messageCount', width: 120 },
    {
      title: t('inbox.lastMessageAt'),
      dataIndex: 'lastMessageAt',
      width: 190,
      render: formatOptionalTime
    },
    {
      title: t('common.actions'),
      width: 230,
      render: (_value, mailbox) => (
        <Space size={4} wrap>
          <Button icon={<KeyOutlined />} onClick={() => setClientConfig(buildMailboxClientConfig(mailbox, config))}>
            {t('inbox.clientConfig')}
          </Button>
          <Button icon={<ThunderboltOutlined />} onClick={() => setWebhookMailbox(mailbox)}>
            {t('inbox.mailboxWebhooks')}
          </Button>
        </Space>
      )
    }
  ];

  const messageColumns: ColumnsType<InboundMessage> = [
    {
      title: t('inbox.receivedAt'),
      dataIndex: 'receivedAt',
      width: 190,
      render: (value: string) => new Date(value).toLocaleString()
    },
    {
      title: t('inbox.subject'),
      dataIndex: 'subject',
      ellipsis: true,
      render: (value: string, message) => (
        <Button type="link" className="table-link" onClick={() => void openMessage(message)}>
          {value || t('inbox.noSubject')}
        </Button>
      )
    },
    { title: t('inbox.sender'), dataIndex: 'sender', width: 220, ellipsis: true },
    { title: t('inbox.mailbox'), dataIndex: 'mailboxAddress', width: 220, ellipsis: true },
    {
      title: t('common.status'),
      dataIndex: 'read',
      width: 100,
      render: (read: boolean) => (
        <Tag color={read ? 'default' : 'blue'}>{read ? t('inbox.read') : t('inbox.unread')}</Tag>
      )
    },
    { title: t('inbox.preview'), dataIndex: 'preview', ellipsis: true }
  ];

  return (
    <>
      <Space direction="vertical" size={20} className="full-width">
        <PageHeader
          title={t('inbox.title')}
          subtitle={t('inbox.subtitle')}
          extra={
            <Space wrap>
              <Button icon={<ReloadOutlined />} loading={loading} onClick={() => void onLoadMessages(selectedMailboxId)}>
                {t('common.refresh')}
              </Button>
              <Button type="primary" icon={<PlusOutlined />} disabled={!domains.length} onClick={openMailboxModal}>
                {t('inbox.createMailbox')}
              </Button>
            </Space>
          }
        />

        {config?.submission?.inboundEnabled === false ? (
          <Alert type="warning" showIcon message={t('inbox.inboundDisabled')} />
        ) : null}

        <Collapse
          className="inbox-help"
          size="small"
          defaultActiveKey={['client']}
          items={[
            {
              key: 'client',
              label: t('inbox.clientHelpTitle'),
              children: (
                <Space direction="vertical" size={8} className="full-width">
                  <Typography.Paragraph type="secondary" className="inbox-help-intro">
                    {t('inbox.clientHelpIntro')}
                  </Typography.Paragraph>
                  <ul className="inbox-help-list">
                    <li>{t('inbox.clientHelpImap')}</li>
                    <li>{t('inbox.clientHelpPop3')}</li>
                    <li>{t('inbox.clientHelpAuth')}</li>
                    <li>{t('inbox.clientHelpSecurity')}</li>
                    <li>{t('inbox.clientHelpPorts')}</li>
                  </ul>
                </Space>
              )
            }
          ]}
        />

        <SectionCard
          title={t('inbox.domainRoutes')}
          extra={<Typography.Text type="secondary">{domains.length}</Typography.Text>}
        >
          {domains.length ? (
            <Table
              rowKey="id"
              columns={domainColumns}
              dataSource={domains}
              pagination={false}
              scroll={{ x: 720 }}
            />
          ) : (
            <EmptyState
              icon={<InboxOutlined />}
              description={t('inbox.noDomain')}
              action={<Button type="primary" onClick={onAddDomain}>{t('common.addDomain')}</Button>}
            />
          )}
        </SectionCard>

        <SectionCard
          title={t('inbox.mailboxes')}
          extra={
            <Typography.Text type="secondary">
              {mailboxes.length}
            </Typography.Text>
          }
        >
          {domains.length ? (
            <Table
              rowKey="id"
              columns={mailboxColumns}
              dataSource={mailboxes}
              pagination={{ pageSize: 5 }}
              scroll={{ x: 1180 }}
            />
          ) : (
            <EmptyState
              icon={<InboxOutlined />}
              description={t('inbox.noDomain')}
              action={<Button type="primary" onClick={onAddDomain}>{t('common.addDomain')}</Button>}
            />
          )}
        </SectionCard>

        <SectionCard
          title={t('inbox.messages')}
          extra={
            <Typography.Text type="secondary">
              {filteredMessages.length} / {messages.length}
            </Typography.Text>
          }
        >
          <div className="page-toolbar inbox-toolbar">
            <Space wrap>
              <Select
                allowClear
                placeholder={t('inbox.mailboxFilter')}
                value={selectedMailboxId || undefined}
                onChange={(value) => void selectMailbox(value || null)}
                options={mailboxes.map((mailbox) => ({ value: mailbox.id, label: mailbox.address }))}
                className="toolbar-select"
              />
              <Input
                allowClear
                prefix={<SearchOutlined />}
                placeholder={t('inbox.searchPlaceholder')}
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                className="toolbar-search"
              />
            </Space>
          </div>
          <Table
            rowKey="id"
            columns={messageColumns}
            dataSource={filteredMessages}
            loading={loading}
            scroll={{ x: 1180 }}
          />
        </SectionCard>
      </Space>

      <Modal
        title={t('inbox.createMailbox')}
        open={mailboxOpen}
        confirmLoading={mailboxLoading}
        onOk={saveMailbox}
        onCancel={closeMailboxModal}
        width={760}
      >
        <Form form={form} layout="vertical">
          <div className="inbox-form-grid">
            <Form.Item
              name="localPart"
              label={t('inbox.localPart')}
              rules={[
                { required: true, message: t('inbox.localPartRequired') },
                { pattern: /^[^@\s]+$/, message: t('inbox.localPartInvalid') }
              ]}
            >
              <Input placeholder="support" />
            </Form.Item>
            <Form.Item name="domain" label={t('domains.domain')} rules={[{ required: true, message: t('inbox.domainRequired') }]}>
              <Select
                options={domains.map((domain) => ({ value: domain.domain, label: domain.domain }))}
                placeholder="example.com"
              />
            </Form.Item>
          </div>
          <Form.Item
            name="password"
            label={t('inbox.password')}
            rules={[
              { required: true, message: t('inbox.passwordRequired') },
              { min: 8, message: t('inbox.passwordMin') }
            ]}
          >
            <Input.Password
              autoComplete="new-password"
              addonAfter={<Button type="link" size="small" onClick={generatePassword}>{t('inbox.generatePassword')}</Button>}
            />
          </Form.Item>
          <div className="inbox-form-grid">
            <Form.Item name="displayName" label={t('inbox.displayName')}>
              <Input placeholder="Support" />
            </Form.Item>
            <Form.Item name="quotaMb" label={t('inbox.quotaMb')}>
              <InputNumber min={0} precision={0} className="full-width" placeholder={t('inbox.unlimited')} addonAfter="MB" />
            </Form.Item>
          </div>
          <Form.Item name="aliases" label={t('inbox.aliases')} extra={t('inbox.aliasesExtra')}>
            <Input.TextArea rows={3} placeholder={'sales\nhelp'} />
          </Form.Item>
          <Form.Item name="forwardTo" label={t('inbox.forwardTo')} extra={t('inbox.forwardToExtra')}>
            <Input.TextArea rows={3} placeholder={'archive@example.net\nops@example.net'} />
          </Form.Item>
          <Form.Item name="keepForwarded" valuePropName="checked">
            <Checkbox>{t('inbox.keepForwarded')}</Checkbox>
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title={catchAllDomain ? `${t('inbox.catchAllTitle')} · ${catchAllDomain.domain}` : t('inbox.catchAllTitle')}
        open={Boolean(catchAllDomain)}
        confirmLoading={catchAllLoading}
        onOk={saveCatchAll}
        onCancel={() => setCatchAllDomain(null)}
      >
        <Form form={catchAllForm} layout="vertical">
          <Form.Item name="catchAllAddress" label={t('inbox.catchAllAddress')} extra={t('inbox.catchAllExtra')}>
            <Input placeholder={`share@${catchAllDomain?.domain || 'example.com'} 或 /dev/null`} />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title={t('inbox.clientConfig')}
        open={Boolean(clientConfig)}
        footer={null}
        onCancel={() => setClientConfig(null)}
        width={760}
      >
        {clientConfig ? (
          <Space direction="vertical" size={16} className="full-width">
            <Alert type="info" showIcon message={t('inbox.clientConfigHelpSummary')} />
            <Descriptions bordered size="small" column={1}>
              <Descriptions.Item label={t('inbox.configUsername')}>
                <ConfigValue value={clientConfig.username} onCopy={onCopy} />
              </Descriptions.Item>
              <Descriptions.Item label={t('inbox.configPassword')}>
                <ConfigValue value={clientConfig.password || t('inbox.passwordNotShown')} onCopy={clientConfig.password ? onCopy : undefined} />
              </Descriptions.Item>
            </Descriptions>
            <Descriptions bordered size="small" column={1} title={t('inbox.incomingConfig')}>
              <Descriptions.Item label={t('inbox.configProtocol')}>{clientConfig.incoming.protocol}</Descriptions.Item>
              <Descriptions.Item label={t('inbox.configHost')}>
                <ConfigValue value={clientConfig.incoming.host} onCopy={onCopy} />
              </Descriptions.Item>
              <Descriptions.Item label={t('inbox.configPort')}>{clientConfig.incoming.port}</Descriptions.Item>
              <Descriptions.Item label={t('inbox.configSecurity')}>{clientConfig.incoming.security}</Descriptions.Item>
              <Descriptions.Item label={t('inbox.configAuthMethod')}>{clientConfig.incoming.authMethod}</Descriptions.Item>
            </Descriptions>
            {clientConfig.pop3 ? (
              <Descriptions bordered size="small" column={1} title={t('inbox.pop3Config')}>
                <Descriptions.Item label={t('inbox.configProtocol')}>{clientConfig.pop3.protocol}</Descriptions.Item>
                <Descriptions.Item label={t('inbox.configHost')}>
                  <ConfigValue value={clientConfig.pop3.host} onCopy={onCopy} />
                </Descriptions.Item>
                <Descriptions.Item label={t('inbox.configPort')}>{clientConfig.pop3.port}</Descriptions.Item>
                <Descriptions.Item label={t('inbox.configSecurity')}>{clientConfig.pop3.security}</Descriptions.Item>
                <Descriptions.Item label={t('inbox.configAuthMethod')}>{clientConfig.pop3.authMethod}</Descriptions.Item>
              </Descriptions>
            ) : null}
            <Descriptions bordered size="small" column={1} title={t('inbox.outgoingConfig')}>
              <Descriptions.Item label={t('inbox.configProtocol')}>{clientConfig.outgoing.protocol}</Descriptions.Item>
              <Descriptions.Item label={t('inbox.configHost')}>
                <ConfigValue value={clientConfig.outgoing.host} onCopy={onCopy} />
              </Descriptions.Item>
              <Descriptions.Item label={t('inbox.configPort')}>{clientConfig.outgoing.port}</Descriptions.Item>
              <Descriptions.Item label={t('inbox.configSecurity')}>{clientConfig.outgoing.security}</Descriptions.Item>
              <Descriptions.Item label={t('inbox.configAuthMethod')}>{clientConfig.outgoing.authMethod}</Descriptions.Item>
            </Descriptions>
          </Space>
        ) : null}
      </Modal>

      <Drawer
        title={webhookMailbox ? `${t('inbox.mailboxWebhooks')} · ${webhookMailbox.address}` : t('inbox.mailboxWebhooks')}
        open={Boolean(webhookMailbox)}
        width="min(1240px, 100vw)"
        destroyOnHidden
        onClose={() => setWebhookMailbox(null)}
      >
        {webhookMailbox ? (
          <Webhooks
            mailboxId={webhookMailbox.id}
            domains={domains}
            mailboxes={mailboxes}
            onCopy={onCopy}
          />
        ) : null}
      </Drawer>

      <Drawer
        title={selectedMessage ? `${t('inbox.messageDetail')} · mh-in-${selectedMessage.id}` : t('inbox.messageDetail')}
        open={Boolean(selectedMessage)}
        width="min(820px, 100vw)"
        onClose={() => setSelectedMessage(null)}
        extra={selectedMessage?.rawMessage ? (
          <Button icon={<CopyOutlined />} onClick={() => onCopy(selectedMessage.rawMessage || '')}>
            {t('inbox.copyRaw')}
          </Button>
        ) : null}
      >
        <Spin spinning={detailLoading}>
          {selectedMessage ? (
            <Space direction="vertical" size={16} className="full-width">
              {detailError ? <Alert type="error" showIcon message={detailError} /> : null}
              <Descriptions bordered size="small" column={1}>
                <Descriptions.Item label={t('inbox.receivedAt')}>{formatOptionalTime(selectedMessage.receivedAt)}</Descriptions.Item>
                <Descriptions.Item label={t('inbox.sender')}>{selectedMessage.sender || '-'}</Descriptions.Item>
                <Descriptions.Item label={t('inbox.recipients')}>{selectedMessage.recipients.join(', ') || '-'}</Descriptions.Item>
                <Descriptions.Item label={t('inbox.mailbox')}>{selectedMessage.mailboxAddress || '-'}</Descriptions.Item>
                <Descriptions.Item label={t('inbox.subject')}>{selectedMessage.subject || '-'}</Descriptions.Item>
                <Descriptions.Item label={t('logs.messageId')}>
                  <Typography.Text code>{selectedMessage.messageId || '-'}</Typography.Text>
                </Descriptions.Item>
              </Descriptions>
              <Tabs
                items={[
                  {
                    key: 'text',
                    label: t('inbox.textBody'),
                    children: <MessageBody value={selectedMessage.textBody} empty={t('inbox.noTextBody')} />
                  },
                  {
                    key: 'html',
                    label: t('inbox.htmlBody'),
                    children: <MessageBody value={selectedMessage.htmlBody} empty={t('inbox.noHtmlBody')} />
                  },
                  {
                    key: 'raw',
                    label: t('inbox.rawMessage'),
                    children: <MessageBody value={selectedMessage.rawMessage} empty={t('inbox.noRawMessage')} />
                  }
                ]}
              />
            </Space>
          ) : null}
        </Spin>
      </Drawer>
    </>
  );

  function openMailboxModal() {
    form.setFieldsValue({
      localPart: '',
      domain: domains[0]?.domain || '',
      password: generateMailboxPassword(),
      displayName: '',
      quotaMb: null,
      aliases: '',
      forwardTo: '',
      keepForwarded: true
    });
    setMailboxOpen(true);
  }

  function closeMailboxModal() {
    setMailboxOpen(false);
    form.resetFields();
  }

  async function saveMailbox() {
    const values = await form.validateFields();
    setMailboxLoading(true);
    try {
      const result = await onCreateMailbox({
        address: `${values.localPart.trim()}@${values.domain}`,
        displayName: values.displayName?.trim(),
        password: values.password,
        aliases: values.aliases,
        forwardTo: values.forwardTo,
        keepForwarded: values.keepForwarded !== false,
        quotaMb: values.quotaMb ?? null
      });
      if (!result?.mailbox) return;
      setClientConfig(result.clientConfig || buildMailboxClientConfig(result.mailbox, config, values.password));
      closeMailboxModal();
    } finally {
      setMailboxLoading(false);
    }
  }

  function generatePassword() {
    form.setFieldValue('password', generateMailboxPassword());
  }

  function openCatchAllModal(domain: Domain) {
    setCatchAllDomain(domain);
    catchAllForm.setFieldsValue({ catchAllAddress: domain.catchAllAddress || '' });
  }

  async function saveCatchAll() {
    if (!catchAllDomain) return;
    const values = await catchAllForm.validateFields();
    setCatchAllLoading(true);
    try {
      await onPatchDomain(catchAllDomain, {
        catchAllAddress: String(values.catchAllAddress || '').trim()
      });
      setCatchAllDomain(null);
      catchAllForm.resetFields();
    } finally {
      setCatchAllLoading(false);
    }
  }

  async function selectMailbox(mailboxId: number | null) {
    setSelectedMailboxId(mailboxId);
    await onLoadMessages(mailboxId);
  }

  async function openMessage(message: InboundMessage) {
    setSelectedMessage(message);
    setDetailError('');
    setDetailLoading(true);
    try {
      const detail = await onLoadMessage(message.id);
      if (detail) setSelectedMessage(detail);
      if (!detail) setDetailError(t('inbox.messageNotFound'));
    } catch (error) {
      setDetailError(error instanceof Error ? error.message : t('inbox.detailLoadFailed'));
    } finally {
      setDetailLoading(false);
    }
  }
}

function ConfigValue({ value, onCopy }: { value: string | number; onCopy?: (value: string) => void }) {
  return (
    <Space>
      <Typography.Text code>{value}</Typography.Text>
      {onCopy ? (
        <Button size="small" icon={<CopyOutlined />} aria-label="Copy" onClick={() => onCopy(String(value))} />
      ) : null}
    </Space>
  );
}

function buildMailboxClientConfig(
  mailbox: InboundMailbox,
  config: RuntimeConfig | null,
  password = ''
): MailboxClientConfig {
  const smtpPort = preferredSubmissionPort(config, ['SMTP + STARTTLS', 'SMTPS']);
  const imapPort = preferredAccessPort(config?.mailAccess?.imap.ports || [], ['IMAPS', 'IMAP + STARTTLS', 'IMAP']);
  const pop3Port = preferredAccessPort(config?.mailAccess?.pop3.ports || [], ['POP3S', 'POP3 + STLS', 'POP3']);
  const accessHost = config?.mailAccess?.host || config?.submission?.host || config?.mailHostname || mailbox.domain;
  return {
    username: mailbox.address,
    password,
    incoming: {
      protocol: 'IMAP',
      host: accessHost,
      port: imapPort?.port || 143,
      security: imapPort?.protocol || 'IMAP + STARTTLS',
      authMethod: 'Normal password',
      username: mailbox.address,
      password
    },
    pop3: {
      protocol: 'POP3',
      host: accessHost,
      port: pop3Port?.port || 110,
      security: pop3Port?.protocol || 'POP3 + STLS',
      authMethod: 'Normal password',
      username: mailbox.address,
      password
    },
    outgoing: {
      protocol: 'SMTP',
      host: config?.submission?.host || config?.mailHostname || mailbox.domain,
      port: smtpPort?.port || 587,
      security: smtpPort?.protocol || 'SMTP + STARTTLS',
      authMethod: 'Normal password',
      username: mailbox.address,
      password
    }
  };
}

function preferredAccessPort(ports: Array<{ port: number; protocol: string }>, protocols: string[]) {
  for (const protocol of protocols) {
    const match = ports.find((port) => port.protocol === protocol && [993, 995].includes(port.port)) ||
      ports.find((port) => port.protocol === protocol);
    if (match) return match;
  }
  return ports[0] || null;
}

function preferredSubmissionPort(config: RuntimeConfig | null, protocols: string[]) {
  const ports = config?.submission?.ports || [];
  for (const protocol of protocols) {
    const match = ports.find((port) => port.protocol === protocol && port.port === 587) ||
      ports.find((port) => port.protocol === protocol && port.port === 465) ||
      ports.find((port) => port.protocol === protocol);
    if (match) return match;
  }
  return ports[0] || null;
}

function generateMailboxPassword() {
  const bytes = new Uint8Array(10);
  if (globalThis.crypto?.getRandomValues) {
    globalThis.crypto.getRandomValues(bytes);
  } else {
    for (let index = 0; index < bytes.length; index += 1) bytes[index] = Math.floor(Math.random() * 256);
  }
  return Array.from(bytes, (value) => (value % 36).toString(36)).join('');
}

function MessageBody({ value, empty }: { value?: string; empty: string }) {
  if (!value) return <EmptyState description={empty} />;
  return <pre className="inbox-message-body">{value}</pre>;
}

function formatOptionalTime(value?: string | null) {
  return value ? new Date(value).toLocaleString() : '-';
}
