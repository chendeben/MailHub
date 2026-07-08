import { CopyOutlined, SearchOutlined } from '@ant-design/icons';
import { Button, Card, DatePicker, Descriptions, Drawer, Empty, Input, Select, Space, Table, Tag, Timeline, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { useMemo, useState } from 'react';

import { useI18n } from '../frontend/i18n/react';
import type { DeliveryAttempt, DeliveryLogEntry, Domain, SendEvent } from '../frontend/types';

const { RangePicker } = DatePicker;

interface SendingLogsProps {
  events: SendEvent[];
  domains: Domain[];
  onCopy: (value: string) => void;
}

export default function SendingLogs({ events, domains, onCopy }: SendingLogsProps) {
  const { t } = useI18n();
  const [domain, setDomain] = useState<string>();
  const [status, setStatus] = useState<string>();
  const [recipient, setRecipient] = useState('');
  const [range, setRange] = useState<[number, number] | null>(null);
  const [selected, setSelected] = useState<SendEvent | null>(null);

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
    { title: t('common.status'), dataIndex: 'status', render: (value) => <StatusTag status={value} />, width: 120 },
    { title: 'Message ID', dataIndex: 'id', render: (value) => <span>mh-{value}</span>, width: 140 },
    { title: t('logs.errorReason'), dataIndex: 'detail', ellipsis: true },
    { title: t('domains.actions'), render: (_, event) => <Button onClick={() => setSelected(event)}>{t('logs.viewDetail')}</Button>, width: 120 }
  ];

  return (
    <>
      <Space direction="vertical" size={16} className="full-width">
        <Card>
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
        </Card>
        <Card title={t('logs.title')}>
          <Table rowKey="id" columns={columns} dataSource={filtered} scroll={{ x: 1300 }} />
        </Card>
      </Space>
      <DeliveryLogDrawer
        event={selected}
        onClose={() => setSelected(null)}
        onCopy={onCopy}
      />
    </>
  );

  function DeliveryLogDrawer({
    event,
    onClose,
    onCopy
  }: {
    event: SendEvent | null;
    onClose: () => void;
    onCopy: (value: string) => void;
  }) {
    const deliveryLog = event?.deliveryLog || [];
    return (
      <Drawer
        title={event ? `${t('logs.detailTitle')} · mh-${event.id}` : t('logs.detailTitle')}
        open={Boolean(event)}
        width={760}
        onClose={onClose}
        extra={event ? (
          <Button icon={<CopyOutlined />} onClick={() => onCopy(formatDeliveryLog(event))}>
            {t('logs.copyDeliveryLog')}
          </Button>
        ) : null}
      >
        {event ? (
          <Space direction="vertical" size={16} className="full-width">
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
            <Card size="small" title={t('logs.deliveryAttempts')} className="delivery-log-card">
              {event.deliveryAttempts?.length ? (
                <Timeline
                  items={event.deliveryAttempts.map((attempt, index) => ({
                    key: `${attempt.raw || attempt.at}-${index}`,
                    color: deliveryAttemptColor(attempt.status),
                    children: <DeliveryAttemptTimelineItem attempt={attempt} />
                  }))}
                />
              ) : (
                <Empty description={t('logs.noDeliveryAttempts')} />
              )}
            </Card>
            <Card size="small" title={t('logs.deliveryLog')} className="delivery-log-card">
              {deliveryLog.length ? (
                <Timeline
                  items={deliveryLog.map((entry, index) => ({
                    key: `${entry.at}-${index}`,
                    color: timelineColor(entry),
                    children: <DeliveryLogTimelineItem entry={entry} />
                  }))}
                />
              ) : (
                <Empty description={t('logs.noDeliveryLog')} />
              )}
            </Card>
          </Space>
        ) : null}
      </Drawer>
    );
  }

  function DeliveryLogTimelineItem({ entry }: { entry: DeliveryLogEntry }) {
    return (
      <div className="delivery-log-entry">
        <Space wrap size={8}>
          <Typography.Text strong>{entry.phase}</Typography.Text>
          {entry.direction ? <Tag>{entry.direction}</Tag> : null}
          {entry.code ? <Tag color={entry.ok === false ? 'red' : 'blue'}>{entry.code}</Tag> : null}
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

  function timelineColor(entry: DeliveryLogEntry) {
    if (entry.ok === false || entry.phase === 'error') return 'red';
    if (entry.phase === 'queue') return 'green';
    if (entry.phase === 'auth') return 'gold';
    return 'blue';
  }

  function StatusTag({ status }: { status: string }) {
    return <Tag color={statusColor(status)}>{statusLabel(status)}</Tag>;
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

  function statusColor(status: string) {
    return {
      queued: 'processing',
      sent: 'success',
      deferred: 'warning',
      bounced: 'error',
      failed: 'error'
    }[status] || 'default';
  }

  function deliveryAttemptColor(status: string) {
    if (status === 'sent') return 'green';
    if (status === 'deferred') return 'gold';
    if (status === 'bounced' || status === 'failed') return 'red';
    return 'blue';
  }
}
