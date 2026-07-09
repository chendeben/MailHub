import { CheckCircleOutlined, ClockCircleOutlined, ExclamationCircleOutlined } from '@ant-design/icons';
import { Button, Col, Progress, Row, Space, Typography } from 'antd';

import { StatusPill } from '../common/StatusPill';
import { buildDomainHealth } from '../../frontend/domain-model.js';
import { useI18n } from '../../frontend/i18n/react';
import type { Domain } from '../../frontend/types';

interface DomainHealthCardProps {
  domain: Domain;
  lastSentAt?: string;
  dnsApiName?: string;
  loading?: boolean;
  onApplyDns: () => void;
  onCheck: () => void;
  onSendTest: () => void;
  onEdit: () => void;
}

export function DomainHealthCard({
  domain,
  lastSentAt,
  dnsApiName,
  loading,
  onApplyDns,
  onCheck,
  onSendTest,
  onEdit
}: DomainHealthCardProps) {
  const { t } = useI18n();
  const health = buildDomainHealth(domain);
  const tone = health.status === 'success' ? 'success' : health.status === 'warning' ? 'warning' : 'error';
  const icon = health.status === 'success'
    ? <CheckCircleOutlined />
    : health.status === 'warning'
      ? <ClockCircleOutlined />
      : <ExclamationCircleOutlined />;

  return (
    <div className="domain-health-card">
      <Row gutter={[24, 24]} align="middle">
        <Col xs={24} xl={16}>
          <Space direction="vertical" size={20} className="full-width">
            <div className="domain-title-row">
              <div className="domain-title-row__text">
                <Typography.Text type="secondary" className="domain-health-card__eyebrow">
                  {t('domainHealth.sendingDomain')}
                </Typography.Text>
                <Typography.Title level={2} className="domain-health-card__title">
                  {domain.domain}
                </Typography.Title>
              </div>
              <StatusPill tone={tone} icon={icon}>
                {domainHealthLabel(health.status, t)}
              </StatusPill>
            </div>

            <div className="domain-health-stats">
              <HealthStat label={t('domains.senderHost')} value={domain.senderHost || '-'} />
              <HealthStat label={t('domains.sendingIp')} value={domain.sendingIp || '-'} />
              <HealthStat label="DKIM selector" value={domain.selector} />
              <HealthStat label={t('domains.lastSent')} value={lastSentAt || t('common.notFound')} />
            </div>

            <div className="health-progress">
              <div>
                <Typography.Text strong>{t('domainHealth.dnsProgress')}</Typography.Text>
                <Typography.Text type="secondary">
                  {health.passed}/{health.total} {t('domainHealth.passed')} · {t('domainHealth.dnsIssues')} {health.dnsIssues}
                </Typography.Text>
              </div>
              <Progress
                percent={health.percent}
                status={health.status === 'error' ? 'exception' : health.status === 'success' ? 'success' : 'active'}
                strokeColor={health.status === 'success' ? 'var(--mh-success)' : health.status === 'error' ? 'var(--mh-danger)' : 'var(--mh-primary)'}
              />
            </div>

            <Space wrap size={8} className="domain-health-meta">
              <StatusPill tone={dnsApiName ? 'info' : 'neutral'}>
                {t('domainHealth.dnsApi')}：{dnsApiName || t('common.notConfigured')}
              </StatusPill>
              <StatusPill tone={health.checkedAt ? 'neutral' : 'warning'}>
                {t('domainDetail.lastCheck')}：{health.checkedAt ? new Date(health.checkedAt).toLocaleString() : t('domainDetail.notChecked')}
              </StatusPill>
            </Space>
          </Space>
        </Col>
        <Col xs={24} xl={8}>
          <div className="domain-action-panel">
            <Button type="primary" block loading={loading} onClick={onApplyDns} disabled={!domain.dnsCredentialId}>
              {t('domainHealth.oneClickDns')}
            </Button>
            <Button block loading={loading} onClick={onCheck}>
              {t('domainHealth.checkNow')}
            </Button>
            <Button block onClick={onSendTest}>
              {t('domainHealth.sendTest')}
            </Button>
            <Button block onClick={onEdit}>
              {t('domainHealth.edit')}
            </Button>
          </div>
        </Col>
      </Row>
    </div>
  );
}

function HealthStat({ label, value }: { label: string; value: string }) {
  return (
    <div className="domain-health-stat">
      <Typography.Text type="secondary" className="domain-health-stat__label">
        {label}
      </Typography.Text>
      <Typography.Text strong className="domain-health-stat__value">
        {value}
      </Typography.Text>
    </div>
  );
}

function domainHealthLabel(status: string, t: (key: string) => string) {
  if (status === 'success') return t('domains.healthy');
  if (status === 'warning') return t('domains.waitingDns');
  return t('domains.needsAction');
}
