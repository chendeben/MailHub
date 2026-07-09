import { ReloadOutlined } from '@ant-design/icons';
import { Alert, Button, Space, Typography } from 'antd';

import { CodeBlock } from '../common/CodeBlock';
import { SectionCard } from '../common/SectionCard';
import { StatusTag } from '../common/StatusTag';
import { getDnsCurrentValues } from '../../frontend/domain-model.js';
import { useI18n } from '../../frontend/i18n/react';
import type { DnsRecord } from '../../frontend/types';

interface DnsRecordCardProps {
  record: DnsRecord;
  loading?: boolean;
  onCopy: (value: string) => void;
  onRecheck: () => void;
}

export function DnsRecordCard({ record, loading, onCopy, onRecheck }: DnsRecordCardProps) {
  const { t } = useI18n();
  const currentValues: string[] = getDnsCurrentValues(record);

  return (
    <SectionCard
      className="dns-record-card"
      title={
        <Space wrap size={8}>
          <span className="dns-record-card__label">{record.label}</span>
          <StatusTag record={record} />
        </Space>
      }
      extra={<Typography.Text code className="dns-record-card__type">{record.type}</Typography.Text>}
    >
      <Space direction="vertical" size={14} className="full-width">
        <DnsValueRow label={t('dnsRecord.hostname')} value={record.host} onCopy={onCopy} />
        <DnsValueRow label={t('dnsRecord.targetValue')} value={record.value || '-'} onCopy={onCopy} />
        <div>
          <Typography.Text type="secondary">{t('dnsRecord.currentValue')}</Typography.Text>
          {currentValues.length ? (
            <Space direction="vertical" size={8} className="full-width value-stack">
              {currentValues.map((value) => (
                <CodeBlock key={value} value={value} onCopy={onCopy} />
              ))}
            </Space>
          ) : (
            <Typography.Paragraph type="secondary" className="dns-empty-value">
              {t('dnsRecord.emptyCurrent')}
            </Typography.Paragraph>
          )}
        </div>
        {record.key === 'ptr' ? (
          <Alert
            type="info"
            showIcon
            message={t('dnsRecord.ptrHint')}
          />
        ) : null}
        {(record.warnings || []).map((warning) => (
          <Alert key={warning} type="warning" showIcon message={warning} />
        ))}
        <Button icon={<ReloadOutlined />} loading={loading} onClick={onRecheck}>
          {t('dnsRecord.recheck')}
        </Button>
      </Space>
    </SectionCard>
  );
}

function DnsValueRow({
  label,
  value,
  onCopy
}: {
  label: string;
  value: string;
  onCopy: (value: string) => void;
}) {
  return (
    <div className="dns-value-row">
      <Typography.Text type="secondary">{label}</Typography.Text>
      <CodeBlock value={value} onCopy={onCopy} />
    </div>
  );
}
