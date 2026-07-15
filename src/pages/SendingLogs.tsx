import { CopyOutlined, SearchOutlined } from '@ant-design/icons';
import { Alert, Button, DatePicker, Descriptions, Drawer, Input, Select, Space, Spin, Table, Tag, Timeline, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { useMemo, useState } from 'react';

import { EmptyState } from '../components/common/EmptyState';
import { PageHeader } from '../components/common/PageHeader';
import { SectionCard } from '../components/common/SectionCard';
import { StatusPill } from '../components/common/StatusPill';
import { buildEventTimeline } from '../frontend/analytics-model.js';
import { useI18n } from '../frontend/i18n/react';
import type { DeliveryAttempt, DeliveryLogEntry, Domain, SendEvent, SendEventTimelineEntry, TrackingLink, WebhookDelivery } from '../frontend/types';

const { RangePicker } = DatePicker;

interface SendingLogsProps {
  events: SendEvent[];
  domains: Domain[];
  onCopy: (value: string) => void;
  onLoadEvent?: (id: number) => Promise<SendEvent | null>;
}

export default function SendingLogs({ events, domains, onCopy, onLoadEvent }: SendingLogsProps) {
  const { t } = useI18n();
  const [domain, setDomain] = useState<string>();
  const [status, setStatus] = useState<string>();
  const [recipient, setRecipient] = useState('');
  const [range, setRange] = useState<[number, number] | null>(null);
  const [selected, setSelected] = useState<SendEvent | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState('');

  const filtered = useMemo(() => {
    return events.filter((event) => {
      const time = new Date(event.createdAt).getTime();
      const matchesRange = !range || (time >= range[0] && time <= range[1]);
      const matchesDomain = !domain || event.domain === domain;
      const matchesStatus = !status || event.status === status;
      const matchesRecipient = !recipient || event.recipients.join(',').includes(recipient);
      return matchesRange && matchesDomain && matchesStatus && matchesRecipient;
    });
  }, [domain, events, range, recipient, status]);

  const columns: ColumnsType<SendEvent> = [
    { title: t('logs.time'), dataIndex: 'createdAt', render: (value) => new Date(value).toLocaleString(), width: 190 },
    { title: t('logs.recipient'), dataIndex: 'recipients', render: (value: string[]) => value.join(', '), ellipsis: true },
    { title: t('logs.domain'), dataIndex: 'domain', width: 180 },
    { title: 'Subject', dataIndex: 'subject', ellipsis: true },
    {
      title: t('common.status'),
      dataIndex: 'status',
      render: (value) => <StatusTag status={value} />,
      width: 120
    },
    {
      title: t('logs.opens'),
      width: 110,
      render: (_, event) => trackingMetric(event, 'opens')
    },
    {
      title: t('logs.clicks'),
      width: 110,
      render: (_, event) => trackingMetric(event, 'clicks')
    },
    { title: 'Message ID', dataIndex: 'id', render: (value) => <span>mh-{value}</span>, width: 140 },
    { title: t('logs.errorReason'), dataIndex: 'detail', ellipsis: true },
    { title: t('domains.actions'), render: (_, event) => <Button onClick={() => void openDetail(event)}>{t('logs.viewDetail')}</Button>, width: 120 }
  ];

  return (
    <>
      <Space direction="vertical" size={20} className="full-width">
        <PageHeader title={t('logs.title')} />

        <SectionCard className="logs-toolbar-card">
          <div className="page-toolbar">
            <Space wrap>
              <RangePicker
                showTime
                onChange={(value) => {
                  if (!value?.[0] || !value?.[1]) return setRange(null);
                  setRange([value[0].valueOf(), value[1].valueOf()]);
                }}
              />
              <Select
                allowClear
                placeholder={t('logs.domainPlaceholder')}
                value={domain}
                onChange={setDomain}
                options={domains.map((item) => ({ value: item.domain, label: item.domain }))}
                className="toolbar-select"
              />
              <Select
                allowClear
                placeholder={t('logs.statusPlaceholder')}
                value={status}
                onChange={setStatus}
                options={[
                  { value: 'queued', label: t('logs.statusQueued') },
                  { value: 'sent', label: t('logs.statusSent') },
                  { value: 'deferred', label: t('logs.statusDeferred') },
                  { value: 'bounced', label: t('logs.statusBounced') },
                  { value: 'failed', label: t('logs.statusFailed') }
                ]}
                className="toolbar-select"
              />
              <Input
                allowClear
                prefix={<SearchOutlined />}
                placeholder={t('logs.recipientPlaceholder')}
                value={recipient}
                onChange={(event) => setRecipient(event.target.value)}
                className="toolbar-search"
              />
            </Space>
          </div>
        </SectionCard>

        <SectionCard
          title={t('logs.title')}
          extra={
            <Typography.Text type="secondary">
              {filtered.length} / {events.length}
            </Typography.Text>
          }
        >
          <Table rowKey="id" columns={columns} dataSource={filtered} scroll={{ x: 1480 }} />
        </SectionCard>
      </Space>

      <DeliveryLogDrawer
        event={selected}
        loading={detailLoading}
        error={detailError}
        onClose={() => setSelected(null)}
        onCopy={onCopy}
      />
    </>
  );

  async function openDetail(event: SendEvent) {
    setSelected(event);
    setDetailError('');
    if (!onLoadEvent) return;
    setDetailLoading(true);
    try {
      const detail = await onLoadEvent(event.id);
      if (detail) setSelected(detail);
      if (!detail) setDetailError(t('logs.detailNotFound'));
    } catch (error) {
      setDetailError(error instanceof Error ? error.message : t('logs.detailLoadFailed'));
    } finally {
      setDetailLoading(false);
    }
  }

  function trackingMetric(event: SendEvent, type: 'opens' | 'clicks') {
    if (!event.tracking?.enabled) return <Tag>{t('logs.trackingDisabledShort')}</Tag>;
    return type === 'opens'
      ? event.tracking.summary?.totalOpens ?? 0
      : event.tracking.summary?.totalClicks ?? 0;
  }

  function DeliveryLogDrawer({
    event,
    loading,
    error,
    onClose,
    onCopy
  }: {
    event: SendEvent | null;
    loading: boolean;
    error: string;
    onClose: () => void;
    onCopy: (value: string) => void;
  }) {
    const deliveryLog = event?.deliveryLog || [];
    const trackingTimeline = buildEventTimeline(event);
    return (
      <Drawer
        title={event ? `${t('logs.detailTitle')} · mh-${event.id}` : t('logs.detailTitle')}
        open={Boolean(event)}
        width="min(760px, 100vw)"
        onClose={onClose}
        extra={event ? (
          <Button icon={<CopyOutlined />} onClick={() => onCopy(formatDeliveryLog(event))}>
            {t('logs.copyDeliveryLog')}
          </Button>
        ) : null}
      >
        {event ? (
          <Spin spinning={loading}>
            <Space direction="vertical" size={16} className="full-width">
              {error ? <Alert type="error" showIcon message={error} /> : null}
              <Descriptions bordered size="small" column={1}>
                <Descriptions.Item label={t('logs.time')}>{new Date(event.createdAt).toLocaleString()}</Descriptions.Item>
                <Descriptions.Item label={t('logs.sender')}>{event.sender}</Descriptions.Item>
                <Descriptions.Item label={t('logs.recipient')}>{event.recipients.join(', ')}</Descriptions.Item>
                <Descriptions.Item label={t('logs.domain')}>{event.domain || '-'}</Descriptions.Item>
                <Descriptions.Item label={t('logs.subject')}>{event.subject || '-'}</Descriptions.Item>
                <Descriptions.Item label={t('common.status')}>
                  <StatusTag status={event.status} />
                </Descriptions.Item>
                <Descriptions.Item label={t('logs.messageId')}>mh-{event.id}</Descriptions.Item>
                <Descriptions.Item label={t('logs.queueId')}>
                  <Typography.Text code>{event.queueId || '-'}</Typography.Text>
                </Descriptions.Item>
                <Descriptions.Item label={t('logs.deliveredAt')}>
                  {event.deliveredAt ? new Date(event.deliveredAt).toLocaleString() : '-'}
                </Descriptions.Item>
                <Descriptions.Item label={t('logs.finalResponse')}>
                  <Typography.Text code className="inline-code-value">{event.detail || '-'}</Typography.Text>
                </Descriptions.Item>
              </Descriptions>
              {event.tracking?.enabled ? (
                <SectionCard title={t('logs.engagement')} className="delivery-log-card">
                  <Descriptions bordered size="small" column={2}>
                    <Descriptions.Item label={t('logs.trackingScope')} span={2}>
                      <StatusPill tone={event.tracking.messageLevel ? 'warning' : 'info'}>
                        {event.tracking.messageLevel ? t('logs.messageLevel') : t('logs.recipientLevel')}
                      </StatusPill>
                    </Descriptions.Item>
                    <Descriptions.Item label={t('logs.opens')}>
                      {event.tracking.summary?.totalOpens || 0}
                    </Descriptions.Item>
                    <Descriptions.Item label={t('logs.clicks')}>
                      {event.tracking.summary?.totalClicks || 0}
                    </Descriptions.Item>
                    <Descriptions.Item label={t('logs.firstOpened')}>
                      {formatOptionalTime(event.tracking.summary?.firstOpenedAt)}
                    </Descriptions.Item>
                    <Descriptions.Item label={t('logs.lastOpened')}>
                      {formatOptionalTime(event.tracking.summary?.lastOpenedAt)}
                    </Descriptions.Item>
                    <Descriptions.Item label={t('logs.firstClicked')}>
                      {formatOptionalTime(event.tracking.summary?.firstClickedAt)}
                    </Descriptions.Item>
                    <Descriptions.Item label={t('logs.lastClicked')}>
                      {formatOptionalTime(event.tracking.summary?.lastClickedAt)}
                    </Descriptions.Item>
                    <Descriptions.Item label={t('logs.proxyOpens')}>
                      {event.tracking.summary?.proxyOpens || 0}
                    </Descriptions.Item>
                    <Descriptions.Item label={t('logs.scannerEvents')}>
                      {event.tracking.summary?.scannerEvents || 0}
                    </Descriptions.Item>
                  </Descriptions>
                  {event.tracking.linksTruncated ? (
                    <Alert type="warning" showIcon message={t('logs.trackingLinksTruncated')} />
                  ) : null}
                  {event.tracking.links?.length ? <TrackingLinksTable links={event.tracking.links} /> : null}
                </SectionCard>
              ) : (
                <SectionCard title={t('logs.engagement')} className="delivery-log-card">
                  <Alert type="info" showIcon message={t('logs.trackingDisabled')} />
                </SectionCard>
              )}
              <SectionCard title={t('logs.trackingTimeline')} className="delivery-log-card">
                {event.tracking?.eventsTruncated ? (
                  <Alert type="warning" showIcon message={t('logs.trackingTimelineTruncated')} />
                ) : null}
                {trackingTimeline.length ? (
                  <Timeline
                    items={trackingTimeline.map((item, index) => ({
                      key: `${item.stage}-${item.at}-${index}`,
                      color: timelineToneColor(item.tone),
                      children: <TrackingTimelineItem item={item} />
                    }))}
                  />
                ) : (
                  <EmptyState description={t('logs.noTrackingTimeline')} />
                )}
              </SectionCard>
              <SectionCard title={t('logs.deliveryAttempts')} className="delivery-log-card">
                {event.deliveryAttempts?.length ? (
                  <Timeline
                    items={event.deliveryAttempts.map((attempt, index) => ({
                      key: `${attempt.raw || attempt.at}-${index}`,
                      color: deliveryAttemptColor(attempt.status),
                      children: <DeliveryAttemptTimelineItem attempt={attempt} />
                    }))}
                  />
                ) : (
                  <EmptyState description={t('logs.noDeliveryAttempts')} />
                )}
              </SectionCard>
              <SectionCard title={t('logs.webhookDeliveries')} className="delivery-log-card">
                {event.webhookDeliveries?.length ? (
                  <WebhookDeliveriesTable deliveries={event.webhookDeliveries} />
                ) : (
                  <EmptyState description={t('logs.noWebhookDeliveries')} />
                )}
              </SectionCard>
              <SectionCard title={t('logs.deliveryLog')} className="delivery-log-card">
                {deliveryLog.length ? (
                  <Timeline
                    items={deliveryLog.map((entry, index) => ({
                      key: `${entry.at}-${index}`,
                      color: timelineColor(entry),
                      children: <DeliveryLogTimelineItem entry={entry} />
                    }))}
                  />
                ) : (
                  <EmptyState description={t('logs.noDeliveryLog')} />
                )}
              </SectionCard>
            </Space>
          </Spin>
        ) : null}
      </Drawer>
    );
  }

  function TrackingTimelineItem({ item }: { item: SendEventTimelineEntry }) {
    return (
      <div className="delivery-log-entry">
        <Space wrap size={8}>
          <Typography.Text strong>{timelineStageLabel(item.stage)}</Typography.Text>
          {item.status ? <StatusPill tone={item.tone}>{webhookStatusLabel(item.status)}</StatusPill> : null}
          <Typography.Text type="secondary">{item.at ? new Date(item.at).toLocaleString() : '-'}</Typography.Text>
        </Space>
        {item.queueId ? <LogLine label="Q" value={item.queueId} /> : null}
        {item.recipient ? <LogLine label="To" value={item.recipient} /> : null}
        {item.relay ? <LogLine label="MX" value={item.relay} /> : null}
        {item.response ? <LogLine label="S" value={item.response} /> : null}
        {item.targetOrigin ? <LogLine label="URL" value={item.targetOrigin} /> : null}
        {item.webhookId ? <LogLine label="WH" value={`#${item.webhookId}${item.responseStatus ? ` · HTTP ${item.responseStatus}` : ''}`} /> : null}
      </div>
    );
  }

  function TrackingLinksTable({ links }: { links: TrackingLink[] }) {
    const columns: ColumnsType<TrackingLink> = [
      {
        title: t('dashboard.link'),
        dataIndex: 'target',
        ellipsis: { showTitle: false },
        render: (value) => <Typography.Text ellipsis={{ tooltip: value }}>{value}</Typography.Text>
      },
      { title: t('logs.clicks'), dataIndex: 'clicks', width: 80 },
      {
        title: t('logs.lastClicked'),
        dataIndex: 'lastClickedAt',
        width: 180,
        render: formatOptionalTime
      }
    ];
    return <Table rowKey="id" size="small" columns={columns} dataSource={links} pagination={false} scroll={{ x: 620 }} />;
  }

  function WebhookDeliveriesTable({ deliveries }: { deliveries: WebhookDelivery[] }) {
    const columns: ColumnsType<WebhookDelivery> = [
      { title: t('webhooks.events'), dataIndex: 'eventType', width: 120 },
      {
        title: t('common.status'),
        dataIndex: 'status',
        width: 130,
        render: (value: string) => <StatusPill tone={webhookTone(value)}>{webhookStatusLabel(value)}</StatusPill>
      },
      { title: t('webhooks.attemptCount'), dataIndex: 'attemptCount', width: 90 },
      { title: 'HTTP', dataIndex: 'responseStatus', width: 90, render: (value) => value ?? '-' },
      {
        title: t('logs.time'),
        dataIndex: 'lastAttemptAt',
        width: 180,
        render: (value, record) => new Date(value || record.createdAt).toLocaleString()
      },
      { title: t('logs.errorReason'), dataIndex: 'error', ellipsis: true, render: (value) => value || '-' }
    ];
    return <Table rowKey="id" size="small" columns={columns} dataSource={deliveries} pagination={false} scroll={{ x: 760 }} />;
  }

  function DeliveryLogTimelineItem({ entry }: { entry: DeliveryLogEntry }) {
    return (
      <div className="delivery-log-entry">
        <Space wrap size={8}>
          <Typography.Text strong>{entry.phase}</Typography.Text>
          {entry.direction ? <Tag>{entry.direction}</Tag> : null}
          {entry.code ? (
            <StatusPill tone={entry.ok === false ? 'error' : 'info'}>{entry.code}</StatusPill>
          ) : null}
          <Typography.Text type="secondary">{entry.at ? new Date(entry.at).toLocaleString() : '-'}</Typography.Text>
        </Space>
        {entry.command ? <LogLine label="C" value={entry.command} /> : null}
        {entry.response ? <LogLine label="S" value={entry.response} /> : null}
        {entry.message ? <LogLine label="-" value={entry.message} /> : null}
        {entry.messageBytes !== undefined ? (
          <Typography.Text type="secondary">{t('logs.messageBytes')}: {entry.messageBytes}</Typography.Text>
        ) : null}
      </div>
    );
  }

  function DeliveryAttemptTimelineItem({ attempt }: { attempt: DeliveryAttempt }) {
    return (
      <div className="delivery-log-entry">
        <Space wrap size={8}>
          <StatusTag status={attempt.status} />
          {attempt.dsn ? <Tag>dsn {attempt.dsn}</Tag> : null}
          <Typography.Text type="secondary">{attempt.at ? new Date(attempt.at).toLocaleString() : '-'}</Typography.Text>
        </Space>
        {attempt.recipient ? <LogLine label="To" value={attempt.recipient} /> : null}
        {attempt.relay ? <LogLine label="MX" value={attempt.relay} /> : null}
        {attempt.response ? <LogLine label="S" value={attempt.response} /> : null}
      </div>
    );
  }

  function LogLine({ label, value }: { label: string; value: string }) {
    return (
      <div className="delivery-log-line">
        <Typography.Text type="secondary">{label}</Typography.Text>
        <Typography.Text code>{value}</Typography.Text>
      </div>
    );
  }

  function formatDeliveryLog(event: SendEvent) {
    const lines = [
      `${t('logs.messageId')}: mh-${event.id}`,
      `${t('logs.time')}: ${new Date(event.createdAt).toLocaleString()}`,
      `${t('logs.sender')}: ${event.sender}`,
      `${t('logs.recipient')}: ${event.recipients.join(', ')}`,
      `${t('logs.subject')}: ${event.subject || '-'}`,
      `${t('common.status')}: ${statusLabel(event.status)}`,
      `${t('logs.queueId')}: ${event.queueId || '-'}`,
      `${t('logs.deliveredAt')}: ${event.deliveredAt ? new Date(event.deliveredAt).toLocaleString() : '-'}`,
      `${t('logs.finalResponse')}: ${event.detail || '-'}`,
      ''
    ];
    if (event.deliveryAttempts?.length) {
      lines.push(t('logs.deliveryAttempts'));
      for (const attempt of event.deliveryAttempts) {
        lines.push(`[${attempt.at || '-'}] ${statusLabel(attempt.status)} ${attempt.recipient || ''}`);
        if (attempt.relay) lines.push(`MX: ${attempt.relay}`);
        if (attempt.dsn) lines.push(`DSN: ${attempt.dsn}`);
        if (attempt.response) lines.push(`S: ${attempt.response}`);
        lines.push('');
      }
    }
    if (event.webhookDeliveries?.length) {
      lines.push(t('logs.webhookDeliveries'));
      for (const delivery of event.webhookDeliveries) {
        lines.push(`[${delivery.lastAttemptAt || delivery.createdAt || '-'}] ${delivery.eventType} ${webhookStatusLabel(delivery.status)}`);
        lines.push(`Webhook: #${delivery.webhookId}`);
        lines.push(`Attempts: ${delivery.attemptCount}`);
        if (delivery.responseStatus) lines.push(`HTTP: ${delivery.responseStatus}`);
        if (delivery.error) lines.push(`${t('logs.errorReason')}: ${delivery.error}`);
        lines.push('');
      }
    }
    if (event.tracking?.enabled) {
      lines.push(t('logs.engagement'));
      lines.push(`${t('logs.opens')}: ${event.tracking.summary?.totalOpens || 0}`);
      lines.push(`${t('logs.clicks')}: ${event.tracking.summary?.totalClicks || 0}`);
      lines.push(`${t('logs.proxyOpens')}: ${event.tracking.summary?.proxyOpens || 0}`);
      lines.push(`${t('logs.scannerEvents')}: ${event.tracking.summary?.scannerEvents || 0}`);
      lines.push('');
    }
    const entries = event.deliveryLog?.length ? event.deliveryLog : [{
      at: event.createdAt,
      phase: 'legacy',
      direction: 'system',
      message: event.detail || t('logs.noDeliveryLog')
    }];
    for (const entry of entries) {
      lines.push(`[${entry.at || '-'}] ${entry.phase}${entry.direction ? `/${entry.direction}` : ''}`);
      if (entry.command) lines.push(`C: ${entry.command}`);
      if (entry.response) lines.push(`S: ${entry.response}`);
      if (entry.message) lines.push(`- ${entry.message}`);
      if (entry.messageBytes !== undefined) lines.push(`${t('logs.messageBytes')}: ${entry.messageBytes}`);
      lines.push('');
    }
    return lines.join('\n').trim();
  }

  function StatusTag({ status }: { status: string }) {
    return <StatusPill tone={statusTone(status)}>{statusLabel(status)}</StatusPill>;
  }

  function statusLabel(status: string) {
    return {
      queued: t('logs.statusQueued'),
      sent: t('logs.statusSent'),
      deferred: t('logs.statusDeferred'),
      bounced: t('logs.statusBounced'),
      failed: t('logs.statusFailed')
    }[status] || status;
  }

  function statusTone(status: string): 'success' | 'warning' | 'error' | 'info' | 'neutral' {
    return {
      queued: 'info',
      sent: 'success',
      deferred: 'warning',
      bounced: 'error',
      failed: 'error'
    }[status] as 'success' | 'warning' | 'error' | 'info' | 'neutral' || 'neutral';
  }

  function timelineStageLabel(stage: string) {
    return {
      submitted: t('logs.stageSubmitted'),
      accepted: t('logs.stageAccepted'),
      delivered: t('logs.stageDelivered'),
      pending: t('logs.stagePending'),
      failed: t('logs.stageFailed'),
      opened: t('logs.stageOpened'),
      clicked: t('logs.stageClicked'),
      webhook: t('logs.stageWebhook')
    }[stage] || stage;
  }

  function webhookStatusLabel(status: string) {
    return {
      pending: t('webhooks.statusPending'),
      processing: t('webhooks.statusProcessing'),
      success: t('webhooks.statusSuccess'),
      dead: t('webhooks.statusDead')
    }[status] || statusLabel(status);
  }

  function webhookTone(status: string): 'success' | 'warning' | 'error' | 'info' | 'neutral' {
    if (status === 'success') return 'success';
    if (status === 'dead') return 'error';
    if (status === 'pending' || status === 'processing') return 'warning';
    return statusTone(status);
  }

  function timelineToneColor(tone: string) {
    if (tone === 'success') return 'green';
    if (tone === 'warning') return 'gold';
    if (tone === 'error') return 'red';
    return 'blue';
  }

  function timelineColor(entry: DeliveryLogEntry) {
    if (entry.ok === false || entry.phase === 'error') return 'red';
    if (entry.phase === 'queue') return 'green';
    if (entry.phase === 'auth') return 'gold';
    return 'blue';
  }

  function deliveryAttemptColor(status: string) {
    if (status === 'sent') return 'green';
    if (status === 'deferred') return 'gold';
    if (status === 'bounced' || status === 'failed') return 'red';
    return 'blue';
  }

  function formatOptionalTime(value?: string | null) {
    return value ? new Date(value).toLocaleString() : '-';
  }
}
