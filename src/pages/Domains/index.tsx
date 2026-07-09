import { DeleteOutlined, EyeOutlined, SearchOutlined } from '@ant-design/icons';
import { Button, Input, Popconfirm, Select, Space, Table, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { useMemo, useState } from 'react';

import { PageHeader } from '../../components/common/PageHeader';
import { SectionCard } from '../../components/common/SectionCard';
import { StatusPill } from '../../components/common/StatusPill';
import { StatusTag } from '../../components/common/StatusTag';
import { buildDomainHealth } from '../../frontend/domain-model.js';
import { useI18n } from '../../frontend/i18n/react';
import type { DnsCredential, Domain, SendEvent } from '../../frontend/types';

interface DomainsPageProps {
  domains: Domain[];
  events: SendEvent[];
  dnsCredentials: DnsCredential[];
  actionLoading?: boolean;
  onViewDetail: (domain: Domain) => void;
  onApplyDns: (domain: Domain) => void;
  onCheck: (domain: Domain) => void;
  onSendTest: (domain: Domain) => void;
  onDelete: (domain: Domain) => void;
  onAddDomain: () => void;
}

export default function DomainsPage({
  domains,
  events,
  dnsCredentials,
  actionLoading,
  onViewDetail,
  onApplyDns,
  onCheck,
  onSendTest,
  onDelete,
  onAddDomain
}: DomainsPageProps) {
  const { t } = useI18n();
  const [query, setQuery] = useState('');
  const [status, setStatus] = useState<string>();
  const credentialName = new Map(dnsCredentials.map((item) => [item.id, item.name]));

  const filtered = useMemo(() => {
    return domains.filter((domain) => {
      const health = buildDomainHealth(domain);
      const matchesQuery = !query || domain.domain.includes(query) || domain.senderHost.includes(query);
      const matchesStatus = !status || health.status === status;
      return matchesQuery && matchesStatus;
    });
  }, [domains, query, status]);

  const columns: ColumnsType<Domain> = [
    {
      title: t('domains.domain'),
      dataIndex: 'domain',
      fixed: 'left',
      width: 190,
      render: (value, domain) => (
        <Button type="link" className="table-link" onClick={() => onViewDetail(domain)}>
          {value}
        </Button>
      )
    },
    { title: t('domains.senderHost'), dataIndex: 'senderHost', width: 190, ellipsis: true },
    { title: t('domains.sendingIp'), dataIndex: 'sendingIp', width: 140 },
    {
      title: t('domains.dnsApi'),
      dataIndex: 'dnsCredentialId',
      width: 150,
      render: (value: number | null) => {
        if (!value) {
          return <StatusPill tone="neutral">{t('common.manual')}</StatusPill>;
        }
        const name = credentialName.get(value);
        return (
          <StatusPill tone={name ? 'info' : 'warning'}>
            {name || t('common.notConfigured')}
          </StatusPill>
        );
      }
    },
    recordColumn('DKIM', 'dkim'),
    recordColumn('SPF', 'spf'),
    recordColumn('DMARC', 'dmarc'),
    {
      title: t('domains.smtp'),
      width: 110,
      render: (_, domain) => (
        <StatusPill tone={domain.status?.verified ? 'success' : 'warning'}>
          {domain.status?.verified ? t('domains.sendable') : t('domains.waitingVerify')}
        </StatusPill>
      )
    },
    {
      title: t('domains.lastSent'),
      width: 180,
      render: (_, domain) => {
        const event = events.find((item) => item.domain === domain.domain);
        return event ? new Date(event.createdAt).toLocaleString() : t('common.notFound');
      }
    },
    {
      title: t('domains.overallStatus'),
      width: 130,
      render: (_, domain) => {
        const health = buildDomainHealth(domain);
        return (
          <StatusPill tone={healthTone(health.status)}>
            {domainHealthLabel(health.status, t)}
          </StatusPill>
        );
      }
    },
    {
      title: t('domains.actions'),
      width: 360,
      fixed: 'right',
      render: (_, domain) => (
        <Space size={8} wrap>
          <Button icon={<EyeOutlined />} onClick={() => onViewDetail(domain)}>
            {t('common.details')}
          </Button>
          <Button type="primary" disabled={!domain.dnsCredentialId} loading={actionLoading} onClick={() => onApplyDns(domain)}>
            {t('domains.oneClickDns')}
          </Button>
          <Button loading={actionLoading} onClick={() => onCheck(domain)}>
            {t('domains.check')}
          </Button>
          <Button onClick={() => onSendTest(domain)}>{t('domains.test')}</Button>
          <Popconfirm title={t('domains.deleteConfirm')} onConfirm={() => onDelete(domain)}>
            <Button danger icon={<DeleteOutlined />} />
          </Popconfirm>
        </Space>
      )
    }
  ];

  return (
    <Space direction="vertical" size={20} className="full-width">
      <PageHeader title={t('domains.title')} />

      <SectionCard className="domains-toolbar-card">
        <div className="page-toolbar">
          <Space wrap>
            <Input
              allowClear
              prefix={<SearchOutlined />}
              placeholder={t('domains.searchPlaceholder')}
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              className="toolbar-search"
            />
            <Select
              allowClear
              placeholder={t('domains.statusPlaceholder')}
              value={status}
              onChange={setStatus}
              options={[
                { value: 'success', label: t('domains.healthy') },
                { value: 'warning', label: t('domains.pending') },
                { value: 'error', label: t('domains.needsAction') }
              ]}
              className="toolbar-select"
            />
          </Space>
          <Button type="primary" onClick={onAddDomain}>
            {t('common.addDomain')}
          </Button>
        </div>
      </SectionCard>

      <SectionCard
        title={t('domains.title')}
        extra={
          <Typography.Text type="secondary">
            {filtered.length} / {domains.length}
          </Typography.Text>
        }
      >
        <Table rowKey="id" columns={columns} dataSource={filtered} scroll={{ x: 1800 }} />
      </SectionCard>
    </Space>
  );
}

function recordColumn(title: string, key: string): ColumnsType<Domain>[number] {
  return {
    title,
    width: 110,
    render: (_, domain) => {
      const record = domain.status?.records?.find((item) => item.key === key);
      if (!record) return <StatusTag status="missing" />;
      return <StatusTag record={record} />;
    }
  };
}

function healthTone(status: string): 'success' | 'warning' | 'error' {
  if (status === 'success') return 'success';
  if (status === 'warning') return 'warning';
  return 'error';
}

function domainHealthLabel(status: string, t: (key: string) => string) {
  if (status === 'success') return t('domains.healthy');
  if (status === 'warning') return t('domains.waitingDns');
  return t('domains.needsAction');
}
