import {
  CopyOutlined,
  DeleteOutlined,
  EditOutlined,
  KeyOutlined,
  PlusOutlined,
  ReloadOutlined,
  ThunderboltOutlined
} from '@ant-design/icons';
import {
  Alert,
  App as AntApp,
  Button,
  Checkbox,
  Drawer,
  Form,
  Input,
  Modal,
  Popconfirm,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Typography
} from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { useCallback, useEffect, useMemo, useState } from 'react';

import { CodeBlock } from '../components/common/CodeBlock';
import { EmptyState } from '../components/common/EmptyState';
import { PageHeader } from '../components/common/PageHeader';
import { SectionCard } from '../components/common/SectionCard';
import { StatusPill } from '../components/common/StatusPill';
import type { StatusTone } from '../components/common/StatusPill';
import { useI18n } from '../frontend/i18n/react';
import { api } from '../frontend/services/api';
import type {
  Domain,
  Webhook,
  WebhookDelivery,
  WebhookDeliveryStatus,
  WebhookEvent,
  WebhookPayload
} from '../frontend/types';

const ALL_EVENTS: WebhookEvent[] = ['sent', 'bounced', 'failed', 'opened', 'clicked'];
const DELIVERY_STATUSES: WebhookDeliveryStatus[] = ['pending', 'processing', 'success', 'dead'];

interface WebhooksProps {
  /** When set, list/create are scoped to this domain (no global page chrome). */
  domainId?: number;
  domains?: Domain[];
  onCopy?: (value: string) => void;
}

interface WebhookFormValues {
  name: string;
  url: string;
  events: WebhookEvent[];
  domainId?: number | null;
  enabled: boolean;
}

interface SecretReveal {
  webhook: Webhook;
  mode: 'created' | 'rotated';
}

export default function Webhooks({ domainId, domains = [], onCopy }: WebhooksProps) {
  const { message } = AntApp.useApp();
  const { t } = useI18n();
  const [webhooks, setWebhooks] = useState<Webhook[]>([]);
  const [deliveries, setDeliveries] = useState<WebhookDelivery[]>([]);
  const [loading, setLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [editing, setEditing] = useState<Webhook | null>(null);
  const [secretReveal, setSecretReveal] = useState<SecretReveal | null>(null);
  const [form] = Form.useForm<WebhookFormValues>();
  const [filterWebhookId, setFilterWebhookId] = useState<number | 'all'>('all');
  const [filterStatus, setFilterStatus] = useState<WebhookDeliveryStatus | 'all'>('all');
  const [filterEvent, setFilterEvent] = useState<WebhookEvent | 'all'>('all');

  const scoped = domainId != null;
  const domainMap = useMemo(() => new Map(domains.map((d) => [d.id, d.domain])), [domains]);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [webhooksResult, deliveriesResult] = await Promise.all([
        api.webhooks(scoped ? domainId : undefined),
        api.webhookDeliveries({ limit: 100 })
      ]);
      const nextWebhooks = webhooksResult.webhooks || [];
      setWebhooks(nextWebhooks);
      const webhookIds = new Set(nextWebhooks.map((w) => w.id));
      const nextDeliveries = (deliveriesResult.deliveries || []).filter((d) =>
        scoped ? webhookIds.has(d.webhookId) : true
      );
      setDeliveries(nextDeliveries);
    } catch (error) {
      message.error(error instanceof Error ? error.message : t('common.error'));
    } finally {
      setLoading(false);
    }
  }, [domainId, message, scoped, t]);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  const lastDeliveryByWebhook = useMemo(() => {
    const map = new Map<number, WebhookDelivery>();
    for (const delivery of deliveries) {
      if (!map.has(delivery.webhookId)) map.set(delivery.webhookId, delivery);
    }
    return map;
  }, [deliveries]);

  const filteredDeliveries = useMemo(() => {
    return deliveries.filter((delivery) => {
      if (filterWebhookId !== 'all' && delivery.webhookId !== filterWebhookId) return false;
      if (filterStatus !== 'all' && delivery.status !== filterStatus) return false;
      if (filterEvent !== 'all' && delivery.eventType !== filterEvent) return false;
      return true;
    });
  }, [deliveries, filterEvent, filterStatus, filterWebhookId]);

  const webhookNameById = useMemo(() => {
    const map = new Map<number, string>();
    for (const webhook of webhooks) map.set(webhook.id, webhook.name);
    return map;
  }, [webhooks]);

  async function copyValue(value: string) {
    if (!value) return;
    if (onCopy) {
      onCopy(value);
      return;
    }
    await navigator.clipboard.writeText(value);
    message.success(t('common.copied'));
  }

  function openCreate() {
    setEditing(null);
    form.setFieldsValue({
      name: '',
      url: '',
      events: [...ALL_EVENTS],
      domainId: scoped ? domainId : undefined,
      enabled: true
    });
    setDrawerOpen(true);
  }

  function openEdit(webhook: Webhook) {
    setEditing(webhook);
    form.setFieldsValue({
      name: webhook.name,
      url: webhook.url,
      events: webhook.events?.length ? [...webhook.events] : [...ALL_EVENTS],
      domainId: webhook.domainId ?? undefined,
      enabled: webhook.enabled
    });
    setDrawerOpen(true);
  }

  function closeDrawer() {
    setDrawerOpen(false);
    setEditing(null);
    form.resetFields();
  }

  async function submitForm() {
    const values = await form.validateFields();
    setActionLoading(true);
    try {
      const payload: WebhookPayload = {
        name: values.name.trim(),
        url: values.url.trim(),
        events: values.events,
        domainId: scoped ? domainId : (values.domainId ?? null),
        enabled: values.enabled
      };
      if (editing) {
        await api.updateWebhook(editing.id, payload);
        message.success(t('actions.webhookUpdated'));
        closeDrawer();
        await loadData();
      } else {
        const result = await api.createWebhook(payload);
        message.success(t('actions.webhookCreated'));
        closeDrawer();
        if (result.webhook?.secret) {
          setSecretReveal({ webhook: result.webhook, mode: 'created' });
        }
        await loadData();
      }
    } catch (error) {
      message.error(error instanceof Error ? error.message : t('common.error'));
    } finally {
      setActionLoading(false);
    }
  }

  async function toggleEnabled(webhook: Webhook, enabled: boolean) {
    setActionLoading(true);
    try {
      await api.updateWebhook(webhook.id, { enabled });
      setWebhooks((current) =>
        current.map((item) => (item.id === webhook.id ? { ...item, enabled } : item))
      );
    } catch (error) {
      message.error(error instanceof Error ? error.message : t('common.error'));
    } finally {
      setActionLoading(false);
    }
  }

  async function deleteWebhook(webhook: Webhook) {
    setActionLoading(true);
    try {
      await api.deleteWebhook(webhook.id);
      message.success(t('actions.webhookDeleted'));
      if (filterWebhookId === webhook.id) setFilterWebhookId('all');
      await loadData();
    } catch (error) {
      message.error(error instanceof Error ? error.message : t('common.error'));
    } finally {
      setActionLoading(false);
    }
  }

  async function rotateSecret(webhook: Webhook) {
    setActionLoading(true);
    try {
      const result = await api.rotateWebhookSecret(webhook.id);
      message.success(t('actions.webhookSecretRotated'));
      if (result.webhook?.secret) {
        setSecretReveal({ webhook: result.webhook, mode: 'rotated' });
      }
      await loadData();
    } catch (error) {
      message.error(error instanceof Error ? error.message : t('common.error'));
    } finally {
      setActionLoading(false);
    }
  }

  async function testWebhook(webhook: Webhook) {
    setActionLoading(true);
    try {
      await api.testWebhook(webhook.id);
      message.success(t('actions.webhookTestQueued'));
      setFilterWebhookId(webhook.id);
      await loadData();
    } catch (error) {
      message.error(error instanceof Error ? error.message : t('common.error'));
    } finally {
      setActionLoading(false);
    }
  }

  async function replayDelivery(delivery: WebhookDelivery) {
    setActionLoading(true);
    try {
      await api.replayWebhookDelivery(delivery.id);
      message.success(t('actions.webhookDeliveryReplayed'));
      await loadData();
    } catch (error) {
      message.error(error instanceof Error ? error.message : t('common.error'));
    } finally {
      setActionLoading(false);
    }
  }

  function viewDeliveries(webhook: Webhook) {
    setFilterWebhookId(webhook.id);
    setFilterStatus('all');
    setFilterEvent('all');
  }

  function scopeLabel(webhook: Webhook) {
    if (webhook.domainId == null) return t('webhooks.scopeAccount');
    const name = domainMap.get(webhook.domainId);
    return name ? `${t('webhooks.scopeDomain')} · ${name}` : t('webhooks.scopeDomain');
  }

  function eventLabel(event: string) {
    if (event === 'sent') return t('webhooks.eventSent');
    if (event === 'bounced') return t('webhooks.eventBounced');
    if (event === 'failed') return t('webhooks.eventFailed');
    if (event === 'opened') return t('webhooks.eventOpened');
    if (event === 'clicked') return t('webhooks.eventClicked');
    return event;
  }

  function deliveryStatusLabel(status: string) {
    if (status === 'pending') return t('webhooks.statusPending');
    if (status === 'processing') return t('webhooks.statusProcessing');
    if (status === 'success') return t('webhooks.statusSuccess');
    if (status === 'dead') return t('webhooks.statusDead');
    return status;
  }

  function deliveryStatusTone(status: string): StatusTone {
    if (status === 'success') return 'success';
    if (status === 'pending') return 'info';
    if (status === 'processing') return 'warning';
    if (status === 'dead') return 'error';
    return 'neutral';
  }

  function lastDeliverySnippet(webhook: Webhook) {
    const delivery = lastDeliveryByWebhook.get(webhook.id);
    if (!delivery) return <Typography.Text type="secondary">—</Typography.Text>;
    const detail = delivery.error
      || (delivery.responseStatus != null ? `HTTP ${delivery.responseStatus}` : '')
      || deliveryStatusLabel(String(delivery.status));
    return (
      <Space size={6} wrap>
        <StatusPill tone={deliveryStatusTone(String(delivery.status))}>
          {deliveryStatusLabel(String(delivery.status))}
        </StatusPill>
        <Typography.Text type="secondary" ellipsis className="inline-code-value">
          {eventLabel(String(delivery.eventType))} · {detail}
        </Typography.Text>
      </Space>
    );
  }

  const endpointColumns: ColumnsType<Webhook> = [
    {
      title: t('webhooks.name'),
      dataIndex: 'name',
      render: (value: string, webhook) => (
        <Space direction="vertical" size={0}>
          <Typography.Text strong>{value}</Typography.Text>
          <Typography.Text type="secondary" code>
            {webhook.secretPrefix}…
          </Typography.Text>
        </Space>
      )
    },
    {
      title: t('webhooks.scope'),
      render: (_, webhook) => scopeLabel(webhook)
    },
    {
      title: t('webhooks.url'),
      dataIndex: 'url',
      ellipsis: true,
      render: (value: string) => (
        <Typography.Text code ellipsis title={value} className="inline-code-value">
          {truncateUrl(value)}
        </Typography.Text>
      )
    },
    {
      title: t('webhooks.events'),
      dataIndex: 'events',
      render: (events: WebhookEvent[]) => (
        <Space size={[4, 4]} wrap>
          {(events || []).map((event) => (
            <Tag key={event}>{eventLabel(event)}</Tag>
          ))}
        </Space>
      )
    },
    {
      title: t('webhooks.enabled'),
      dataIndex: 'enabled',
      width: 100,
      render: (enabled: boolean, webhook) => (
        <Switch
          checked={enabled}
          loading={actionLoading}
          onChange={(checked) => void toggleEnabled(webhook, checked)}
          checkedChildren={t('webhooks.enabled')}
          unCheckedChildren={t('webhooks.disabled')}
        />
      )
    },
    {
      title: t('webhooks.lastAttemptAt'),
      render: (_, webhook) => lastDeliverySnippet(webhook)
    },
    {
      title: t('webhooks.actions'),
      fixed: 'right',
      width: 280,
      render: (_, webhook) => (
        <Space wrap size={4}>
          <Button size="small" icon={<ThunderboltOutlined />} onClick={() => void testWebhook(webhook)}>
            {t('webhooks.test')}
          </Button>
          <Button size="small" onClick={() => viewDeliveries(webhook)}>
            {t('webhooks.viewDeliveries')}
          </Button>
          <Button size="small" icon={<EditOutlined />} onClick={() => openEdit(webhook)} />
          <Popconfirm title={t('webhooks.rotateConfirm')} onConfirm={() => void rotateSecret(webhook)}>
            <Button size="small" icon={<KeyOutlined />} />
          </Popconfirm>
          <Popconfirm title={t('webhooks.deleteConfirm')} onConfirm={() => void deleteWebhook(webhook)}>
            <Button size="small" danger icon={<DeleteOutlined />} />
          </Popconfirm>
        </Space>
      )
    }
  ];

  const deliveryColumns: ColumnsType<WebhookDelivery> = [
    {
      title: t('webhooks.createdAt'),
      dataIndex: 'createdAt',
      width: 170,
      render: (value: string) => (value ? new Date(value).toLocaleString() : '—')
    },
    {
      title: t('webhooks.name'),
      dataIndex: 'webhookId',
      render: (id: number) => webhookNameById.get(id) || `#${id}`
    },
    {
      title: t('webhooks.events'),
      dataIndex: 'eventType',
      render: (value: string) => <Tag>{eventLabel(value)}</Tag>
    },
    {
      title: t('common.status'),
      dataIndex: 'status',
      render: (value: string) => (
        <StatusPill tone={deliveryStatusTone(value)}>{deliveryStatusLabel(value)}</StatusPill>
      )
    },
    {
      title: t('webhooks.attemptCount'),
      dataIndex: 'attemptCount',
      width: 90
    },
    {
      title: t('webhooks.responseStatus'),
      dataIndex: 'responseStatus',
      width: 100,
      render: (value: number | null | undefined) => (value != null ? value : '—')
    },
    {
      title: t('webhooks.error'),
      dataIndex: 'error',
      ellipsis: true,
      render: (value: string, row) => value || row.responseBodyPreview || '—'
    },
    {
      title: t('webhooks.lastAttemptAt'),
      dataIndex: 'lastAttemptAt',
      width: 170,
      render: (value?: string | null) => (value ? new Date(value).toLocaleString() : '—')
    },
    {
      title: t('webhooks.actions'),
      fixed: 'right',
      width: 110,
      render: (_, delivery) => (
        <Button
          size="small"
          disabled={delivery.status === 'processing'}
          onClick={() => void replayDelivery(delivery)}
        >
          {t('webhooks.replay')}
        </Button>
      )
    }
  ];

  const secret = secretReveal?.webhook.secret || '';
  const sampleVerifier = buildSignatureSample(secret || 'whsec_your_secret');

  return (
    <Space direction="vertical" size={20} className="full-width">
      {!scoped ? (
        <PageHeader
          title={t('webhooks.title')}
          subtitle={t('webhooks.subtitle')}
          extra={
            <Space>
              <Button icon={<ReloadOutlined />} onClick={() => void loadData()} loading={loading}>
                {t('common.refresh')}
              </Button>
              <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>
                {t('webhooks.create')}
              </Button>
            </Space>
          }
        />
      ) : (
        <Space direction="vertical" size={12} className="full-width">
          <Alert type="info" showIcon message={t('webhooks.domainOverrideHelp')} />
          <Space>
            <Button icon={<ReloadOutlined />} onClick={() => void loadData()} loading={loading}>
              {t('common.refresh')}
            </Button>
            <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>
              {t('webhooks.create')}
            </Button>
          </Space>
        </Space>
      )}

      {!scoped ? (
        <Alert type="info" showIcon message={t('webhooks.domainOverrideHelp')} />
      ) : null}

      <SectionCard
        title={t('webhooks.listTitle')}
        extra={<StatusPill tone="neutral">{webhooks.length}</StatusPill>}
      >
        {webhooks.length ? (
          <Table
            rowKey="id"
            columns={endpointColumns}
            dataSource={webhooks}
            loading={loading}
            scroll={{ x: 1200 }}
            pagination={{ pageSize: 10 }}
          />
        ) : (
          <EmptyState
            description={t('webhooks.empty')}
            action={
              <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>
                {t('webhooks.create')}
              </Button>
            }
          />
        )}
      </SectionCard>

      <SectionCard title={t('webhooks.deliveriesTitle')}>
        <Space wrap className="full-width" style={{ marginBottom: 16 }}>
          <Select
            style={{ minWidth: 180 }}
            value={filterWebhookId}
            onChange={setFilterWebhookId}
            options={[
              { value: 'all', label: t('webhooks.allWebhooks') },
              ...webhooks.map((w) => ({ value: w.id, label: w.name }))
            ]}
            placeholder={t('webhooks.deliveriesFilterWebhook')}
          />
          <Select
            style={{ minWidth: 140 }}
            value={filterStatus}
            onChange={setFilterStatus}
            options={[
              { value: 'all', label: t('webhooks.allStatuses') },
              ...DELIVERY_STATUSES.map((status) => ({
                value: status,
                label: deliveryStatusLabel(status)
              }))
            ]}
            placeholder={t('webhooks.deliveriesFilterStatus')}
          />
          <Select
            style={{ minWidth: 140 }}
            value={filterEvent}
            onChange={setFilterEvent}
            options={[
              { value: 'all', label: t('webhooks.allEvents') },
              ...ALL_EVENTS.map((event) => ({ value: event, label: eventLabel(event) }))
            ]}
            placeholder={t('webhooks.deliveriesFilterEvent')}
          />
        </Space>
        {filteredDeliveries.length ? (
          <Table
            rowKey="id"
            columns={deliveryColumns}
            dataSource={filteredDeliveries}
            loading={loading}
            scroll={{ x: 1100 }}
            pagination={{ pageSize: 10 }}
          />
        ) : (
          <EmptyState description={t('webhooks.deliveriesEmpty')} />
        )}
      </SectionCard>

      {!scoped ? (
        <SectionCard title={t('webhooks.docsTitle')}>
          <Space direction="vertical" size={12} className="full-width">
            <Typography.Text>{t('webhooks.docsSignature')}</Typography.Text>
            <Typography.Text>{t('webhooks.docsEvents')}</Typography.Text>
            <Typography.Text type="secondary">{t('webhooks.urlHint')}</Typography.Text>
            <CodeBlock value={buildSignatureSample('whsec_your_secret')} onCopy={copyValue} />
          </Space>
        </SectionCard>
      ) : null}

      <Drawer
        title={editing ? t('webhooks.editTitle') : t('webhooks.createTitle')}
        width={520}
        open={drawerOpen}
        onClose={closeDrawer}
        destroyOnHidden
        footer={
          <div className="drawer-footer">
            <Button onClick={closeDrawer}>{t('common.cancel')}</Button>
            <Button type="primary" loading={actionLoading} onClick={() => void submitForm()}>
              {editing ? t('common.save') : t('webhooks.create')}
            </Button>
          </div>
        }
      >
        <Form form={form} layout="vertical" initialValues={{ enabled: true, events: ALL_EVENTS }}>
          <Form.Item
            name="name"
            label={t('webhooks.name')}
            rules={[{ required: true, message: t('webhooks.nameRequired') }]}
          >
            <Input placeholder={t('webhooks.namePlaceholder')} />
          </Form.Item>
          <Form.Item
            name="url"
            label={t('webhooks.url')}
            extra={t('webhooks.urlHint')}
            rules={[{ required: true, message: t('webhooks.urlRequired') }]}
          >
            <Input placeholder={t('webhooks.urlPlaceholder')} />
          </Form.Item>
          <Form.Item
            name="events"
            label={t('webhooks.events')}
            rules={[{ required: true, type: 'array', min: 1, message: t('webhooks.eventsRequired') }]}
          >
            <Checkbox.Group
              options={ALL_EVENTS.map((event) => ({
                value: event,
                label: eventLabel(event)
              }))}
            />
          </Form.Item>
          {!scoped ? (
            <Form.Item name="domainId" label={t('webhooks.domain')} extra={t('webhooks.domainAccount')}>
              <Select
                allowClear
                placeholder={t('webhooks.domainAccount')}
                options={domains.map((domain) => ({
                  value: domain.id,
                  label: domain.domain
                }))}
              />
            </Form.Item>
          ) : null}
          <Form.Item name="enabled" label={t('webhooks.enabled')} valuePropName="checked">
            <Switch />
          </Form.Item>
        </Form>
      </Drawer>

      <Modal
        title={
          secretReveal?.mode === 'rotated'
            ? t('webhooks.secretRotatedTitle')
            : t('webhooks.secretCreatedTitle')
        }
        open={Boolean(secretReveal)}
        onCancel={() => setSecretReveal(null)}
        footer={[
          <Button key="close" onClick={() => setSecretReveal(null)}>
            {t('common.cancel')}
          </Button>,
          <Button
            key="copy"
            type="primary"
            icon={<CopyOutlined />}
            onClick={() => void copyValue(secret)}
          >
            {t('webhooks.copySecret')}
          </Button>
        ]}
      >
        <Space direction="vertical" size={16} className="full-width">
          <Alert type="error" showIcon message={t('webhooks.secretCreatedWarning')} />
          <div>
            <Typography.Text type="secondary">{t('webhooks.secret')}</Typography.Text>
            <CodeBlock value={secret} onCopy={copyValue} />
          </div>
          <div>
            <Typography.Text type="secondary">{t('webhooks.docsSignature')}</Typography.Text>
            <CodeBlock value={sampleVerifier} onCopy={copyValue} />
          </div>
        </Space>
      </Modal>
    </Space>
  );
}

function truncateUrl(url: string, max = 48) {
  if (!url) return '';
  if (url.length <= max) return url;
  return `${url.slice(0, max - 1)}…`;
}

function buildSignatureSample(secret: string) {
  return `// Verify X-MailHub-Signature (Node.js)
const crypto = require('crypto');

function verify(rawBody, signatureHeader, secret = ${JSON.stringify(secret)}) {
  const parts = Object.fromEntries(
    signatureHeader.split(',').map((p) => p.trim().split('='))
  );
  const signed = \`\${parts.t}.\${rawBody}\`;
  const expected = crypto.createHmac('sha256', secret).update(signed).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(parts.v1, 'hex'), Buffer.from(expected, 'hex'));
}`;
}
