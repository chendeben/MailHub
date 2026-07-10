import { Area, Bar, Column, Line, Pie } from '@ant-design/plots';
import { Alert, Col, List, Progress, Row, Space, Table, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';

import { EmptyState } from '../components/common/EmptyState';
import { MetricCard } from '../components/common/MetricCard';
import { PageHeader } from '../components/common/PageHeader';
import { SectionCard } from '../components/common/SectionCard';
import { StatusPill } from '../components/common/StatusPill';
import {
  buildDashboardSummary,
  buildDeliveryFunnel,
  buildDomainRanking,
  buildEngagementSummary,
  buildEngagementTrend,
  buildHourlyHeatmap,
  buildStatusDistribution,
  buildTopLinks,
  buildTrendSeries
} from '../frontend/analytics-model.js';
import { buildDomainHealth } from '../frontend/domain-model.js';
import { useI18n } from '../frontend/i18n/react';
import { brandColors } from '../frontend/theme';
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
  const deliveryFunnel = buildDeliveryFunnel(analytics);
  const engagement = buildEngagementSummary(analytics);
  const engagementTrend = buildEngagementTrend(analytics);
  const engagementTrendData = engagementTrend.flatMap((item) => [
    { date: item.date, type: t('dashboard.opens'), value: item.opens },
    { date: item.date, type: t('dashboard.clicks'), value: item.clicks }
  ]);
  const topLinks = buildTopLinks(analytics);
  const failureReasons = analytics?.failureReasons || [];
  const lastSentLabel = summary.lastSentAt
    ? new Date(summary.lastSentAt).toLocaleString()
    : t('common.notFound');

  const columns: ColumnsType<SendEvent> = [
    { title: 'Time', dataIndex: 'createdAt', render: (value) => new Date(value).toLocaleString() },
    { title: 'Recipient', dataIndex: 'recipients', render: (value: string[]) => value.join(', ') },
    { title: 'Domain', dataIndex: 'domain' },
    { title: 'Subject', dataIndex: 'subject', ellipsis: true },
    {
      title: t('common.status'),
      dataIndex: 'status',
      render: (value) => (
        <StatusPill tone={statusTone(value)}>{statusLabel(value, t)}</StatusPill>
      )
    }
  ];
  const linkColumns: ColumnsType<(typeof topLinks)[number]> = [
    {
      title: t('dashboard.link'),
      dataIndex: 'target',
      ellipsis: { showTitle: false },
      render: (value) => <Typography.Text ellipsis={{ tooltip: value }}>{value || '-'}</Typography.Text>
    },
    { title: t('dashboard.uniqueClicks'), dataIndex: 'uniqueClicks', width: 110 },
    { title: t('dashboard.totalClicks'), dataIndex: 'clicks', width: 100 },
    {
      title: t('dashboard.lastClicked'),
      dataIndex: 'lastClickedAt',
      width: 180,
      render: (value) => value ? new Date(value).toLocaleString() : '-'
    }
  ];

  return (
    <Space direction="vertical" size={20} className="full-width">
      {config?.usingDefaultAdminPassword ? (
        <Alert type="warning" showIcon message={t('dashboard.defaultPasswordWarning')} />
      ) : null}

      <PageHeader
        title={t('dashboard.title')}
        extra={
          <StatusPill tone={summary.smtpReady ? 'success' : 'warning'}>
            {t('dashboard.smtpStatus')}:{' '}
            {summary.smtpReady ? t('dashboard.smtpReady') : t('dashboard.smtpNotConfigured')}
          </StatusPill>
        }
      />

      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} lg={6}>
          <MetricCard label={t('dashboard.todaySent')} value={summary.today} />
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <MetricCard
            label={t('dashboard.successRate')}
            value={`${summary.successRate}%`}
            hint={`${t('dashboard.bounceRate')} ${summary.bounceRate}% · ${t('dashboard.complaintRate')} ${summary.complaintRate}%`}
          />
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <MetricCard label={t('dashboard.verifiedDomains')} value={summary.verifiedDomains} />
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <MetricCard
            label={t('dashboard.dnsIssues')}
            value={summary.dnsIssues}
            tone={summary.dnsIssues > 0 ? 'warning' : 'default'}
            hint={summary.dnsIssues > 0 ? t('dashboard.dnsActionHint') : undefined}
          />
        </Col>
      </Row>

      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} xl={6}>
          <MetricCard
            label={t('dashboard.openRate')}
            value={`${engagement.openRate}%`}
            hint={`${engagement.uniqueOpens} ${t('dashboard.unique')} · ${engagement.totalOpens} ${t('dashboard.total')}`}
          />
        </Col>
        <Col xs={24} sm={12} xl={6}>
          <MetricCard
            label={t('dashboard.clickRate')}
            value={`${engagement.clickRate}%`}
            hint={`${engagement.uniqueClicks} ${t('dashboard.unique')} · ${engagement.totalClicks} ${t('dashboard.total')}`}
          />
        </Col>
        <Col xs={24} sm={12} xl={6}>
          <MetricCard
            label={t('dashboard.clickToOpenRate')}
            value={`${engagement.clickToOpenRate}%`}
            hint={`${t('dashboard.trackedDelivered')} ${engagement.trackedDelivered}`}
          />
        </Col>
        <Col xs={24} sm={12} xl={6}>
          <MetricCard
            label={t('dashboard.measuredActivity')}
            value={engagement.totalOpens + engagement.totalClicks}
            hint={`${t('dashboard.proxyOpens')} ${engagement.proxyOpens} · ${t('dashboard.scannerEvents')} ${engagement.scannerEvents}`}
          />
        </Col>
      </Row>

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={15}>
          <SectionCard title={t('dashboard.engagementTrend')} className="chart-card">
            {engagementTrendData.some((item) => item.value > 0) ? (
              <Line
                data={engagementTrendData}
                xField="date"
                yField="value"
                colorField="type"
                height={300}
                axis={{ y: { title: false }, x: { title: false } }}
                scale={{ color: { range: [brandColors.chartPrimary, brandColors.chartSuccess] } }}
                tooltip={{ title: 'date' }}
                legend={{ color: { position: 'top' } }}
              />
            ) : (
              <EmptyState description={t('dashboard.noEngagement')} />
            )}
          </SectionCard>
        </Col>
        <Col xs={24} xl={9}>
          <SectionCard title={t('dashboard.topLinks')}>
            {topLinks.length ? (
              <Table
                rowKey="fingerprint"
                size="small"
                columns={linkColumns}
                dataSource={topLinks}
                pagination={false}
                scroll={{ x: 640 }}
              />
            ) : (
              <EmptyState description={t('dashboard.noEngagement')} />
            )}
          </SectionCard>
        </Col>
      </Row>

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={15}>
          <SectionCard title={t('dashboard.deliveryFunnel')}>
            {deliveryFunnel.length ? (
              <div className="delivery-funnel">
                {deliveryFunnel.map((item) => (
                  <div className="delivery-funnel-row" key={item.stage}>
                    <div className="delivery-funnel-row__meta">
                      <StatusPill tone={item.tone}>{deliveryStageLabel(item.stage, t)}</StatusPill>
                      <Typography.Text strong>{item.total}</Typography.Text>
                    </div>
                    <Progress percent={item.rate} size="small" showInfo={false} status={item.tone === 'error' ? 'exception' : 'normal'} />
                    <Typography.Text type="secondary">{item.rate}%</Typography.Text>
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState description={t('dashboard.noTrend')} />
            )}
          </SectionCard>
        </Col>
        <Col xs={24} xl={9}>
          <SectionCard title={t('dashboard.failureReasons')}>
            {failureReasons.length ? (
              <List
                dataSource={failureReasons}
                renderItem={(item) => (
                  <List.Item>
                    <List.Item.Meta
                      title={<Typography.Text ellipsis>{item.reason}</Typography.Text>}
                      description={
                        <Typography.Text type="secondary">
                          {t('metrics.total')}: {item.total} · {item.lastSeenAt ? new Date(item.lastSeenAt).toLocaleString() : '-'}
                        </Typography.Text>
                      }
                    />
                  </List.Item>
                )}
              />
            ) : (
              <EmptyState description={t('dashboard.noFailures')} />
            )}
          </SectionCard>
        </Col>
      </Row>

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={15}>
          <SectionCard title={t('dashboard.trend')} className="chart-card">
            {trendData.length ? (
              <Area
                data={trendData}
                xField="date"
                yField="value"
                colorField="type"
                shapeField="smooth"
                height={316}
                axis={{ y: { title: false }, x: { title: false } }}
                scale={{
                  color: {
                    range: [brandColors.chartPrimary, brandColors.chartSuccess, brandColors.chartDanger]
                  }
                }}
                tooltip={{ title: 'date' }}
                legend={{ color: { position: 'top' } }}
              />
            ) : (
              <EmptyState description={t('dashboard.noTrend')} />
            )}
          </SectionCard>
        </Col>
        <Col xs={24} xl={9}>
          <SectionCard title={t('dashboard.statusDistribution')} className="chart-card">
            {statusData.length ? (
              <Pie
                data={statusData}
                angleField="value"
                colorField="label"
                radius={0.68}
                innerRadius={0.48}
                height={316}
                marginLeft={24}
                marginRight={24}
                marginTop={8}
                marginBottom={8}
                scale={{
                  color: {
                    range: [brandColors.chartSuccess, brandColors.chartDanger, brandColors.chartWarning]
                  }
                }}
                label={{
                  text: (datum: { label?: string; value?: number }) =>
                    `${datum.label || ''}${datum.value != null ? ` ${datum.value}` : ''}`,
                  position: 'outside',
                  transform: [{ type: 'overlapDodgeY' }],
                  style: {
                    fontSize: 12,
                    textAlign: 'center'
                  },
                  connector: true
                }}
                legend={{ color: { position: 'bottom' } }}
                tooltip={{
                  title: (datum: { label?: string }) => datum.label || '',
                  items: [
                    (datum: { value?: number }) => ({
                      name: t('metrics.total'),
                      value: datum.value ?? 0
                    })
                  ]
                }}
              />
            ) : (
              <EmptyState description={t('dashboard.noTrend')} />
            )}
          </SectionCard>
        </Col>
      </Row>

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={12}>
          <SectionCard title={t('dashboard.domainRanking')} className="chart-card">
            {rankingData.length ? (
              <Bar
                data={rankingData}
                xField="total"
                yField="domain"
                height={312}
                colorField="domain"
                scale={{ color: { range: [brandColors.chartPrimary] } }}
                label={{ text: 'total', position: 'right' }}
                axis={{ x: { title: false }, y: { title: false } }}
                legend={false}
              />
            ) : (
              <EmptyState description={t('dashboard.noDomains')} />
            )}
          </SectionCard>
        </Col>
        <Col xs={24} xl={12}>
          <SectionCard title={t('dashboard.hourlyHeatmap')} className="chart-card">
            {hourlyData.length ? (
              <Column
                data={hourlyData}
                xField="hour"
                yField="total"
                height={312}
                colorField="total"
                scale={{ color: { range: [brandColors.chartTrack, brandColors.chartPrimary] } }}
                axis={{ x: { title: false }, y: { title: false } }}
                tooltip={{ title: 'hour' }}
                legend={false}
              />
            ) : (
              <EmptyState description={t('dashboard.noTrend')} />
            )}
          </SectionCard>
        </Col>
      </Row>

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={9}>
          <SectionCard title={t('dashboard.recentFailures')}>
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
              <EmptyState description={t('dashboard.noFailures')} />
            )}
          </SectionCard>
        </Col>
        <Col xs={24} xl={15}>
          <SectionCard title={t('dashboard.domainHealth')}>
            <Space direction="vertical" className="full-width">
              {domains.slice(0, 6).map((domain) => {
                const health = buildDomainHealth(domain);
                return (
                  <div className="health-row" key={domain.id}>
                    <div>
                      <Typography.Text strong>{domain.domain}</Typography.Text>
                      <Typography.Text type="secondary">DNS {health.passed}/{health.total}</Typography.Text>
                    </div>
                    <StatusPill tone={domainHealthTone(health.status)}>
                      {domainHealthLabel(health.status, t)}
                    </StatusPill>
                  </div>
                );
              })}
              {!domains.length ? <EmptyState description={t('dashboard.noDomains')} /> : null}
            </Space>
          </SectionCard>
        </Col>
      </Row>

      <SectionCard
        title={t('dashboard.recentLogs')}
        extra={
          <Typography.Text type="secondary">
            {t('dashboard.lastSentAt')}: {lastSentLabel}
          </Typography.Text>
        }
      >
        <Table rowKey="id" columns={columns} dataSource={events.slice(0, 8)} pagination={false} scroll={{ x: 900 }} />
      </SectionCard>
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

function statusTone(status: string): 'success' | 'warning' | 'error' | 'info' | 'neutral' {
  if (status === 'queued') return 'info';
  if (status === 'sent') return 'success';
  if (status === 'deferred') return 'warning';
  if (status === 'bounced' || status === 'failed') return 'error';
  return 'neutral';
}

function domainHealthLabel(status: string, t: (key: string) => string) {
  if (status === 'success') return t('domains.healthy');
  if (status === 'warning') return t('domains.waitingDns');
  return t('domains.needsAction');
}

function domainHealthTone(status: string): 'success' | 'warning' | 'error' {
  if (status === 'success') return 'success';
  if (status === 'warning') return 'warning';
  return 'error';
}

function deliveryStageLabel(stage: string, t: (key: string) => string) {
  if (stage === 'submitted') return t('dashboard.stageSubmitted');
  if (stage === 'accepted') return t('dashboard.stageAccepted');
  if (stage === 'delivered') return t('dashboard.stageDelivered');
  if (stage === 'pending') return t('dashboard.stagePending');
  if (stage === 'failed') return t('dashboard.stageFailed');
  return stage;
}
