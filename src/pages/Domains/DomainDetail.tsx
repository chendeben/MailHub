import { ArrowLeftOutlined, CopyOutlined } from '@ant-design/icons';
import {
  Alert,
  Button,
  Collapse,
  Descriptions,
  Form,
  Input,
  Modal,
  Row,
  Col,
  Select,
  Space,
  Table,
  Tabs,
  Typography
} from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { useMemo, useState } from 'react';

import { CodeBlock } from '../../components/common/CodeBlock';
import { EmptyState } from '../../components/common/EmptyState';
import { SectionCard } from '../../components/common/SectionCard';
import { StatusPill } from '../../components/common/StatusPill';
import { DomainHealthCard } from '../../components/domain/DomainHealthCard';
import { DnsRecordCard } from '../../components/domain/DnsRecordCard';
import { getVisibleDnsRecords } from '../../frontend/domain-model.js';
import { useI18n } from '../../frontend/i18n/react';
import type {
  ApiToken,
  DnsCredential,
  DnsRecord,
  Domain,
  DomainPatchPayload,
  RuntimeConfig,
  SendEvent,
  SmtpCredential,
  SmtpRelay
} from '../../frontend/types';

interface DomainDetailProps {
  domain: Domain;
  config: RuntimeConfig | null;
  smtpCredential: SmtpCredential | null;
  apiTokens: ApiToken[];
  events: SendEvent[];
  dnsCredentials: DnsCredential[];
  smtpRelays: SmtpRelay[];
  actionLoading?: boolean;
  initialTab?: string;
  onBack: () => void;
  onApplyDns: (domain: Domain) => void;
  onCheck: (domain: Domain) => void;
  onSendTest: (domain: Domain) => void;
  onPatchDomain: (domain: Domain, values: DomainPatchPayload) => Promise<void>;
  onCopy: (value: string) => void;
  onDelete: (domain: Domain) => void;
}

export default function DomainDetail({
  domain,
  config,
  smtpCredential,
  apiTokens,
  events,
  dnsCredentials,
  smtpRelays,
  actionLoading,
  initialTab,
  onBack,
  onApplyDns,
  onCheck,
  onSendTest,
  onPatchDomain,
  onCopy,
  onDelete
}: DomainDetailProps) {
  const { t } = useI18n();
  const [activeTab, setActiveTab] = useState(initialTab || 'overview');
  const [editOpen, setEditOpen] = useState(false);
  const [form] = Form.useForm<DomainPatchPayload>();
  const dnsApiName = dnsCredentials.find((item) => item.id === domain.dnsCredentialId)?.name;
  const smtpRelayName = smtpRelays.find((item) => item.id === domain.smtpRelayId)?.name;
  const domainEvents = events.filter((event) => event.domain === domain.domain);
  const records = useMemo(() => orderedRecords(domain.status?.records || []), [domain.status?.records]);

  function openEdit() {
    form.setFieldsValue({
      selector: domain.selector,
      dnsCredentialId: domain.dnsCredentialId,
      smtpRelayId: domain.smtpRelayId,
      senderHost: domain.senderHost,
      sendingIp: domain.sendingIp,
      spfExtra: domain.spfExtra,
      dmarcPolicy: domain.dmarcPolicy,
      dmarcRua: domain.dmarcRua
    });
    setEditOpen(true);
  }

  async function saveEdit() {
    const values = await form.validateFields();
    await onPatchDomain(domain, {
      ...values,
      dnsCredentialId: values.dnsCredentialId ?? null,
      smtpRelayId: values.smtpRelayId ?? null
    });
    setEditOpen(false);
  }

  return (
    <Space direction="vertical" size={20} className="full-width">
      <Button icon={<ArrowLeftOutlined />} onClick={onBack}>
        {t('domainDetail.back')}
      </Button>
      <DomainHealthCard
        domain={domain}
        lastSentAt={domainEvents[0] ? new Date(domainEvents[0].createdAt).toLocaleString() : undefined}
        dnsApiName={dnsApiName}
        loading={actionLoading}
        onApplyDns={() => onApplyDns(domain)}
        onCheck={() => onCheck(domain)}
        onSendTest={() => onSendTest(domain)}
        onEdit={openEdit}
      />
      <Tabs
        activeKey={activeTab}
        onChange={setActiveTab}
        className="domain-detail-tabs"
        items={[
          { key: 'overview', label: 'Overview', children: <OverviewTab domain={domain} events={domainEvents} smtpRelayName={smtpRelayName} onDelete={() => onDelete(domain)} /> },
          {
            key: 'dns',
            label: 'DNS Records',
            children: (
              <DnsRecordsTab
                domain={domain}
                records={records}
                loading={actionLoading}
                onCopy={onCopy}
                onCheck={() => onCheck(domain)}
              />
            )
          },
          {
            key: 'smtp-api',
            label: 'SMTP / API',
            children: (
              <SmtpApiTab
                domain={domain}
                config={config}
                smtpCredential={smtpCredential}
                apiTokens={apiTokens}
                onCopy={onCopy}
              />
            )
          },
          { key: 'logs', label: 'Sending Logs', children: <SendingLogsTab events={domainEvents} /> },
          { key: 'guide', label: 'Integration Guide', children: <IntegrationGuideTab domain={domain} config={config} apiTokens={apiTokens} /> },
          { key: 'webhooks', label: 'Webhooks', children: <Placeholder title="Webhooks" /> }
        ]}
      />
      <Modal title={t('domainDetail.editTitle')} open={editOpen} onCancel={() => setEditOpen(false)} onOk={saveEdit} confirmLoading={actionLoading}>
        <Form form={form} layout="vertical">
          <Form.Item name="dnsCredentialId" label={t('domains.dnsApi')}>
            <Select
              allowClear
              placeholder={t('addDomain.manualDns')}
              options={dnsCredentials.map((credential) => ({
                value: credential.id,
                label: credential.name
              }))}
            />
          </Form.Item>
          <Form.Item name="smtpRelayId" label={t('smtpRelay.domainDefault')}>
            <Select
              allowClear
              placeholder={t('smtpRelay.useResolutionOrder')}
              options={smtpRelays.map((relay) => ({
                value: relay.id,
                label: relayLabel(relay, t)
              }))}
            />
          </Form.Item>
          <Form.Item name="selector" label="DKIM selector" rules={[{ required: true, message: t('addDomain.selectorRequired') }]}>
            <Input />
          </Form.Item>
          <Form.Item name="senderHost" label={t('domains.senderHost')} rules={[{ required: true, message: t('addDomain.senderHostRequired') }]}>
            <Input />
          </Form.Item>
          <Form.Item name="sendingIp" label={t('domains.sendingIp')} rules={[{ required: true, message: t('addDomain.sendingIpRequired') }]}>
            <Input />
          </Form.Item>
          <Form.Item name="dmarcPolicy" label="DMARC">
            <Select options={['none', 'quarantine', 'reject'].map((value) => ({ value, label: value }))} />
          </Form.Item>
          <Form.Item name="spfExtra" label={t('addDomain.spfExtra')}>
            <Input.TextArea rows={3} />
          </Form.Item>
          <Form.Item name="dmarcRua" label="DMARC rua">
            <Input placeholder="mailto:dmarc@example.com" />
          </Form.Item>
        </Form>
      </Modal>
    </Space>
  );
}

function OverviewTab({
  domain,
  events,
  smtpRelayName,
  onDelete
}: {
  domain: Domain;
  events: SendEvent[];
  smtpRelayName?: string;
  onDelete: () => void;
}) {
  const { t } = useI18n();
  return (
    <Row gutter={[16, 16]}>
      <Col xs={24} lg={16}>
        <SectionCard title={t('domainDetail.overview')}>
          <Descriptions column={1}>
            <Descriptions.Item label={t('domains.domain')}>{domain.domain}</Descriptions.Item>
            <Descriptions.Item label={t('domains.senderHost')}>{domain.senderHost}</Descriptions.Item>
            <Descriptions.Item label={t('domains.sendingIp')}>{domain.sendingIp}</Descriptions.Item>
            <Descriptions.Item label={t('smtpRelay.domainDefault')}>{smtpRelayName || t('smtpRelay.useResolutionOrder')}</Descriptions.Item>
            <Descriptions.Item label="DKIM selector">{domain.selector}</Descriptions.Item>
            <Descriptions.Item label={t('domains.lastSent')}>{events[0] ? new Date(events[0].createdAt).toLocaleString() : t('common.notFound')}</Descriptions.Item>
          </Descriptions>
        </SectionCard>
      </Col>
      <Col xs={24} lg={8}>
        <SectionCard title={t('domainDetail.danger')} className="domain-danger-card">
          <Space direction="vertical" className="full-width" size={12}>
            <Typography.Text type="secondary">{t('domainDetail.deleteHint')}</Typography.Text>
            <Button danger block onClick={onDelete}>
              {t('common.delete')}
            </Button>
          </Space>
        </SectionCard>
      </Col>
    </Row>
  );
}

function DnsRecordsTab({
  domain,
  records,
  loading,
  onCopy,
  onCheck
}: {
  domain: Domain;
  records: DnsRecord[];
  loading?: boolean;
  onCopy: (value: string) => void;
  onCheck: () => void;
}) {
  const { t } = useI18n();
  const liveEntries = Object.entries(domain.status?.live || {});
  const copyAll = records.map((record) => `${record.host}\t${record.type}\t${record.value || ''}`).join('\n');

  return (
    <Row gutter={[16, 16]} align="top">
      <Col xs={24} xl={15}>
        <Space direction="vertical" size={12} className="full-width">
          {records.length ? records.map((record) => (
              <DnsRecordCard key={record.key} record={record} loading={loading} onCopy={onCopy} onRecheck={onCheck} />
          )) : (
            <SectionCard>
              <EmptyState
                description={t('domainDetail.noDnsResult')}
                action={
                  <Button type="primary" onClick={onCheck}>{t('domainHealth.checkNow')}</Button>
                }
              />
            </SectionCard>
          )}
        </Space>
      </Col>
      <Col xs={24} xl={9}>
        <SectionCard
          title={t('domainDetail.currentDnsResult')}
          extra={
            <Space>
              <Button size="small" onClick={onCheck}>{t('domainDetail.recheckAll')}</Button>
              <Button size="small" icon={<CopyOutlined />} disabled={!copyAll} onClick={() => onCopy(copyAll)}>
                {t('domainDetail.copyAll')}
              </Button>
            </Space>
          }
        >
          <Space direction="vertical" size={16} className="full-width">
            <StatusPill tone={domain.status?.checkedAt ? 'neutral' : 'warning'}>
              {t('domainDetail.lastCheck')}：{domain.status?.checkedAt ? new Date(domain.status.checkedAt).toLocaleString() : t('domainDetail.notChecked')}
            </StatusPill>
            {liveEntries.length ? (
              <Collapse
                items={liveEntries.map(([key, values]) => ({
                  key,
                  label: liveLabel(key, t),
                  children: values.length ? (
                    <Space direction="vertical" className="full-width" size={8}>
                      {values.map((value) => (
                        <CodeBlock key={value} value={value} onCopy={onCopy} />
                      ))}
                    </Space>
                  ) : (
                    <Typography.Text type="secondary">{t('domainDetail.notFoundRecord')}</Typography.Text>
                  )
                }))}
              />
            ) : (
              <EmptyState description={t('domainDetail.noPublicDns')} />
            )}
            {domain.status?.warnings?.length ? (
              <Alert type="warning" showIcon message={t('domainDetail.needAttention')} description={domain.status.warnings.join('\n')} />
            ) : null}
          </Space>
        </SectionCard>
      </Col>
    </Row>
  );
}

function SmtpApiTab({
  domain,
  config,
  smtpCredential,
  apiTokens,
  onCopy
}: {
  domain: Domain;
  config: RuntimeConfig | null;
  smtpCredential: SmtpCredential | null;
  apiTokens: ApiToken[];
  onCopy: (value: string) => void;
}) {
  const { t } = useI18n();
  const apiEndpoint = `${config?.appBaseUrl || window.location.origin}/api/send`;
  return (
    <Row gutter={[16, 16]}>
      <Col xs={24} lg={12}>
        <SectionCard title="SMTP">
          <Descriptions column={1}>
            <Descriptions.Item label="SMTP Host">{copyable(config?.submission?.host || '-', onCopy)}</Descriptions.Item>
            <Descriptions.Item label="SMTP Port">
              <Space wrap size={6}>
                {(config?.submission?.ports || []).map((item) => (
                  <StatusPill key={item.port} tone="info">
                    {item.port} · {item.protocol}
                  </StatusPill>
                ))}
              </Space>
            </Descriptions.Item>
            <Descriptions.Item label="Username">{copyable(smtpCredential?.username || config?.submission?.username || '-', onCopy)}</Descriptions.Item>
            <Descriptions.Item label="Password">{smtpCredential?.password ? copyable(smtpCredential.password, onCopy) : t('domainDetail.noSmtpPassword')}</Descriptions.Item>
            <Descriptions.Item label="TLS / SSL">{config?.submission?.tls ? 'TLS' : 'STARTTLS'}</Descriptions.Item>
          </Descriptions>
        </SectionCard>
      </Col>
      <Col xs={24} lg={12}>
        <SectionCard title="API">
          <Descriptions column={1}>
            <Descriptions.Item label="API Endpoint">{copyable(apiEndpoint, onCopy)}</Descriptions.Item>
            <Descriptions.Item label="API Token">{apiTokens[0] ? `${apiTokens[0].tokenPrefix}...` : t('domainDetail.noApiToken')}</Descriptions.Item>
            <Descriptions.Item label="From">noreply@{domain.domain}</Descriptions.Item>
          </Descriptions>
        </SectionCard>
      </Col>
    </Row>
  );
}

function SendingLogsTab({ events }: { events: SendEvent[] }) {
  const { t } = useI18n();
  const columns: ColumnsType<SendEvent> = [
    { title: t('logs.time'), dataIndex: 'createdAt', render: (value) => new Date(value).toLocaleString() },
    { title: t('logs.recipient'), dataIndex: 'recipients', render: (value: string[]) => value.join(', ') },
    { title: 'Subject', dataIndex: 'subject', ellipsis: true },
    {
      title: t('common.status'),
      dataIndex: 'status',
      render: (value) => (
        <StatusPill tone={sendStatusTone(value)}>{sendStatusLabel(value, t)}</StatusPill>
      )
    },
    { title: t('logs.errorReason'), dataIndex: 'detail', ellipsis: true }
  ];
  return (
    <SectionCard title={t('logs.title')}>
      <Table rowKey="id" columns={columns} dataSource={events} scroll={{ x: 900 }} />
    </SectionCard>
  );
}

function IntegrationGuideTab({
  domain,
  config,
  apiTokens
}: {
  domain: Domain;
  config: RuntimeConfig | null;
  apiTokens: ApiToken[];
}) {
  const { t } = useI18n();
  const token = apiTokens[0] ? `${apiTokens[0].tokenPrefix}...` : '<USER_API_TOKEN>';
  const endpoint = `${config?.appBaseUrl || window.location.origin}/api/send`;
  const code = `curl -X POST ${endpoint} \\
  -H 'Authorization: Bearer ${token}' \\
  -H 'Content-Type: application/json' \\
  -d '{
    "from": "noreply@${domain.domain}",
    "to": "user@example.com",
    "subject": "Hello from MailHub",
    "text": "Signed with DKIM and queued by MailHub."
  }'`;
  return (
    <SectionCard title={t('domainDetail.apiExample')}>
      <CodeBlock value={code} />
    </SectionCard>
  );
}

function Placeholder({ title }: { title: string }) {
  const { t } = useI18n();
  return (
    <SectionCard>
      <EmptyState description={`${title} ${t('domainDetail.placeholder')}`} />
    </SectionCard>
  );
}

function orderedRecords(records: DnsRecord[]) {
  return getVisibleDnsRecords(records);
}

function sendStatusLabel(status: string, t: (key: string) => string) {
  if (status === 'queued') return t('logs.statusQueued');
  if (status === 'sent') return t('logs.statusSent');
  if (status === 'deferred') return t('logs.statusDeferred');
  if (status === 'bounced') return t('logs.statusBounced');
  if (status === 'failed') return t('logs.statusFailed');
  return status || t('dashboard.statusUnknown');
}

function sendStatusTone(status: string): 'success' | 'warning' | 'error' | 'info' | 'neutral' {
  if (status === 'queued') return 'info';
  if (status === 'sent') return 'success';
  if (status === 'deferred') return 'warning';
  if (status === 'bounced' || status === 'failed') return 'error';
  return 'neutral';
}

function liveLabel(key: string, t: (key: string) => string) {
  return {
    rootTxt: t('dnsRecord.rootTxt'),
    verificationTxt: t('dnsRecord.verificationTxt'),
    dkimTxt: t('dnsRecord.dkimTxt'),
    dmarcTxt: t('dnsRecord.dmarcTxt'),
    senderA: t('dnsRecord.senderA'),
    ptr: t('dnsRecord.ptr')
  }[key] || key;
}

function relayLabel(relay: SmtpRelay, t: (key: string) => string) {
  return `${relay.name}${relay.isDefault ? ` · ${t('smtpRelay.default')}` : ''} · ${relay.host}:${relay.port}`;
}

function copyable(value: string, onCopy: (value: string) => void) {
  return (
    <Space>
      <Typography.Text code>{value}</Typography.Text>
      <Button size="small" icon={<CopyOutlined />} onClick={() => onCopy(value)} />
    </Space>
  );
}
