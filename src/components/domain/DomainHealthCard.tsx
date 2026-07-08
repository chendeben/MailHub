import { CheckCircleOutlined, ClockCircleOutlined, ExclamationCircleOutlined } from '@ant-design/icons';
import { Button, Card, Col, Progress, Row, Space, Statistic, Tag, Typography } from 'antd';

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
  const icon = health.status === 'success'
    ? <CheckCircleOutlined />
    : health.status === 'warning'
      ? <ClockCircleOutlined />
      : <ExclamationCircleOutlined />;

  return (
    <Card className="domain-health-card">
      <Row gutter={[24, 24]} align="middle">
        <Col xs={24} xl={16}>
          <Space direction="vertical" size={16} className="full-width">
            <div className="domain-title-row">
              <div>
                <Typography.Text type="secondary">{t('domainHealth.sendingDomain')}</Typography.Text>
                <Typography.Title level={2}>{domain.domain}</Typography.Title>
              </div>
              <Tag color={health.status === 'success' ? 'success' : health.status === 'warning' ? 'warning' : 'error'} icon={icon}>
                {domainHealthLabel(health.status, t)}
              </Tag>
            </div>
            <Row gutter={[16, 16]}>
              <Col xs={12} md={6}>
                <Statistic title={t('domains.senderHost')} value={domain.senderHost || '-'} valueStyle={{ fontSize: 14 }} />
              </Col>
              <Col xs={12} md={6}>
                <Statistic title={t('domains.sendingIp')} value={domain.sendingIp || '-'} valueStyle={{ fontSize: 14 }} />
              </Col>
              <Col xs={12} md={6}>
                <Statistic title="DKIM selector" value={domain.selector} valueStyle={{ fontSize: 14 }} />
              </Col>
              <Col xs={12} md={6}>
                <Statistic title={t('domains.lastSent')} value={lastSentAt || t('common.notFound')} valueStyle={{ fontSize: 14 }} />
              </Col>
            </Row>
            <div className="health-progress">
              <div>
                <Typography.Text strong>{t('domainHealth.dnsProgress')}</Typography.Text>
                <Typography.Text type="secondary">
                  {health.passed}/{health.total} {t('domainHealth.passed')} · {t('domainHealth.dnsIssues')} {health.dnsIssues}
                </Typography.Text>
              </div>
              <Progress percent={health.percent} status={health.status === 'error' ? 'exception' : 'active'} />
            </div>
            <Space wrap>
              <Tag>{t('domainHealth.dnsApi')}：{dnsApiName || t('common.notConfigured')}</Tag>
              <Tag>{t('domainDetail.lastCheck')}：{health.checkedAt ? new Date(health.checkedAt).toLocaleString() : t('domainDetail.notChecked')}</Tag>
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
    </Card>
  );
}

function domainHealthLabel(status: string, t: (key: string) => string) {
  if (status === 'success') return t('domains.healthy');
  if (status === 'warning') return t('domains.waitingDns');
  return t('domains.needsAction');
}
