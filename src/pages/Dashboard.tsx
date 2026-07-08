import { Area, Bar, Column, Pie } from '@ant-design/plots';
import { Alert, Card, Col, Empty, List, Row, Space, Table, Tag, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';

import {
  buildDashboardSummary,
  buildDomainRanking,
  buildHourlyHeatmap,
  buildStatusDistribution,
  buildTrendSeries
} from '../frontend/analytics-model.js';
import { buildDomainHealth } from '../frontend/domain-model.js';
import { useI18n } from '../frontend/i18n/react';
import type { Analytics, Domain, RuntimeConfig, SendEvent, SmtpCredential } from '../frontend/types';

interface DashboardProps {
  analytics: Analytics | null;
  domains: Domain[];
  events: SendEvent[];
  config: RuntimeConfig | null;
  smtpCredential: SmtpCredential | null;
}

export default function Dashboard({ analytics, domains, events, config, smtpCredential }: DashboardProps) {
  const { t } = useI18n();
  const summary = buildDashboardSummary({ analytics, domains, events, config, smtpCredential });
  const trendSeries = buildTrendSeries(analytics);
  const trendData = trendSeries.flatMap((item) => [
    { date: item.date, type: t('metrics.total'), value: item.total },
    { date: item.date, type: t('metrics.accepted'), value: item.accepted },
    { date: item.date, type: t('metrics.failed'), value: item.failed }
  ]);
  const statusData = buildStatusDistribution(analytics).map((item) => ({
    ...item,
    label: statusLabel(item.status, t)
  }));
  const rankingData = buildDomainRanking(analytics);
  const hourlyData = buildHourlyHeatmap(analytics);

  const cards = [
    { label: t('dashboard.verifiedDomains'), value: summary.verifiedDomains },
    { label: t('dashboard.todaySent'), value: summary.today },
    { label: t('dashboard.successRate'), value: `${summary.successRate}%` },
    { label: t('dashboard.bounceRate'), value: `${summary.bounceRate}%` },
    { label: t('dashboard.complaintRate'), value: `${summary.complaintRate}%` },
    { label: t('dashboard.lastSentAt'), value: summary.lastSentAt ? new Date(summary.lastSentAt).toLocaleString() : t('common.notFound') },
    { label: t('dashboard.dnsIssues'), value: summary.dnsIssues },
    { label: t('dashboard.smtpStatus'), value: summary.smtpReady ? t('dashboard.smtpReady') : t('dashboard.smtpNotConfigured') }
  ];

  const columns: ColumnsType<SendEvent> = [
    { title: 'Time', dataIndex: 'createdAt', render: (value) => new Date(value).toLocaleString() },
    { title: 'Recipient', dataIndex: 'recipients', render: (value: string[]) => value.join(', ') },
    { title: 'Domain', dataIndex: 'domain' },
    { title: 'Subject', dataIndex: 'subject', ellipsis: true },
    {
      title: t('common.status'),
      dataIndex: 'status',
      render: (value) => <Tag color={statusColor(value)}>{statusLabel(value, t)}</Tag>
    }
  ];

  return (
    <Space direction="vertical" size={20} className="full-width">
      {config?.usingDefaultAdminPassword ? (
        <Alert type="warning" showIcon message={t('dashboard.defaultPasswordWarning')} />
      ) : null}
      <Row gutter={[16, 16]}>
        {cards.map((card) => (
          <Col xs={24} sm={12} lg={6} key={card.label}>
            <Card className="metric-card">
              <Typography.Text type="secondary">{card.label}</Typography.Text>
              <Typography.Title level={3} className="metric-value">
                {card.value}
              </Typography.Title>
            </Card>
          </Col>
        ))}
      </Row>
      <Row gutter={[16, 16]}>
        <Col xs={24} xl={15}>
          <Card title={t('dashboard.trend')} className="chart-card">
            {trendData.length ? (
              <Area
                data={trendData}
                xField="date"
                yField="value"
                colorField="type"
                shapeField="smooth"
                height={316}
                axis={{ y: { title: false }, x: { title: false } }}
                scale={{ color: { range: ['#1677ff', '#52c41a', '#ff4d4f'] } }}
                tooltip={{ title: 'date' }}
                legend={{ color: { position: 'top' } }}
              />
            ) : (
              <Empty description={t('dashboard.noTrend')} />
            )}
          </Card>
        </Col>
        <Col xs={24} xl={9}>
          <Card title={t('dashboard.statusDistribution')} className="chart-card">
            {statusData.length ? (
              <Pie
                data={statusData}
                angleField="value"
                colorField="label"
                innerRadius={0.64}
                height={316}
                scale={{ color: { range: ['#52c41a', '#ff4d4f', '#faad14'] } }}
                label={{ text: 'value', position: 'outside' }}
                legend={{ color: { position: 'bottom' } }}
              />
            ) : (
              <Empty description={t('dashboard.noTrend')} />
            )}
          </Card>
        </Col>
      </Row>
      <Row gutter={[16, 16]}>
        <Col xs={24} xl={12}>
          <Card title={t('dashboard.domainRanking')} className="chart-card">
            {rankingData.length ? (
              <Bar
                data={rankingData}
                xField="total"
                yField="domain"
                height={312}
                colorField="domain"
                label={{ text: 'total', position: 'right' }}
                axis={{ x: { title: false }, y: { title: false } }}
                legend={false}
              />
            ) : (
              <Empty description={t('dashboard.noDomains')} />
            )}
          </Card>
        </Col>
        <Col xs={24} xl={12}>
          <Card title={t('dashboard.hourlyHeatmap')} className="chart-card">
            {hourlyData.length ? (
              <Column
                data={hourlyData}
                xField="hour"
                yField="total"
                height={312}
                colorField="total"
                scale={{ color: { range: ['#dbeafe', '#1677ff'] } }}
                axis={{ x: { title: false }, y: { title: false } }}
                tooltip={{ title: 'hour' }}
                legend={false}
              />
            ) : (
              <Empty description={t('dashboard.noTrend')} />
            )}
          </Card>
        </Col>
      </Row>
      <Row gutter={[16, 16]}>
        <Col xs={24} xl={9}>
          <Card title={t('dashboard.recentFailures')}>
            {analytics?.recentFailures?.length ? (
              <List
                dataSource={analytics.recentFailures}
                renderItem={(item) => (
                  <List.Item>
                    <List.Item.Meta
                      title={<Typography.Text ellipsis>{item.subject || item.domain || '-'}</Typography.Text>}
                      description={
                        <Space direction="vertical" size={2}>
                          <Typography.Text type="secondary">{new Date(item.createdAt).toLocaleString()}</Typography.Text>
                          <Typography.Text type="danger" ellipsis>{item.detail}</Typography.Text>
                        </Space>
                      }
                    />
                  </List.Item>
                )}
              />
            ) : (
              <Empty description={t('dashboard.noFailures')} />
            )}
          </Card>
        </Col>
        <Col xs={24} xl={15}>
          <Card title={t('dashboard.domainHealth')}>
            <Space direction="vertical" className="full-width">
              {domains.slice(0, 6).map((domain) => {
                const health = buildDomainHealth(domain);
                return (
                  <div className="health-row" key={domain.id}>
                    <div>
                      <Typography.Text strong>{domain.domain}</Typography.Text>
                      <Typography.Text type="secondary">DNS {health.passed}/{health.total}</Typography.Text>
                    </div>
                    <Tag color={health.status === 'success' ? 'success' : health.status === 'warning' ? 'warning' : 'error'}>
                      {domainHealthLabel(health.status, t)}
                    </Tag>
                  </div>
                );
              })}
              {!domains.length ? <Empty description={t('dashboard.noDomains')} /> : null}
            </Space>
          </Card>
        </Col>
      </Row>
      <Card title={t('dashboard.recentLogs')}>
        <Table rowKey="id" columns={columns} dataSource={events.slice(0, 8)} pagination={false} scroll={{ x: 900 }} />
      </Card>
    </Space>
  );
}

function statusLabel(status: string, t: (key: string) => string) {
  if (status === 'queued') return t('logs.statusQueued');
  if (status === 'sent') return t('logs.statusSent');
  if (status === 'deferred') return t('logs.statusDeferred');
  if (status === 'bounced') return t('logs.statusBounced');
  if (status === 'failed') return t('logs.statusFailed');
  return status || t('dashboard.statusUnknown');
}

function statusColor(status: string) {
  if (status === 'queued') return 'processing';
  if (status === 'sent') return 'success';
  if (status === 'deferred') return 'warning';
  if (status === 'bounced' || status === 'failed') return 'error';
  return 'default';
}

function domainHealthLabel(status: string, t: (key: string) => string) {
  if (status === 'success') return t('domains.healthy');
  if (status === 'warning') return t('domains.waitingDns');
  return t('domains.needsAction');
}
