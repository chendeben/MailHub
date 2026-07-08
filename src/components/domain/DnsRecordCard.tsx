import { CopyOutlined, ReloadOutlined } from '@ant-design/icons';
import { Alert, Button, Card, Space, Tooltip, Typography } from 'antd';

import { useI18n } from '../../frontend/i18n/react';
import type { DnsRecord } from '../../frontend/types';
import { StatusTag } from '../common/StatusTag';

interface DnsRecordCardProps {
  record: DnsRecord;
  loading?: boolean;
  onCopy: (value: string) => void;
  onRecheck: () => void;
}

export function DnsRecordCard({ record, loading, onCopy, onRecheck }: DnsRecordCardProps) {
  const { t } = useI18n();
  const currentValues = Array.isArray(record.current)
    ? record.current
    : record.current
      ? [record.current]
      : [];

  return (
    <Card
      className="dns-record-card"
      title={
        <Space wrap>
          <span>{record.label}</span>
          <StatusTag record={record} />
        </Space>
      }
      extra={<Typography.Text code>{record.type}</Typography.Text>}
    >
      <Space direction="vertical" size={14} className="full-width">
        <DnsValueRow label={t('dnsRecord.hostname')} value={record.host} onCopy={onCopy} />
        <DnsValueRow label={t('dnsRecord.targetValue')} value={record.value || '-'} onCopy={onCopy} />
        <div>
          <Typography.Text type="secondary">{t('dnsRecord.currentValue')}</Typography.Text>
          {currentValues.length ? (
            <Space direction="vertical" size={8} className="full-width value-stack">
              {currentValues.map((value) => (
                <Typography.Paragraph key={value} code copyable className="dns-code-block">
                  {value}
                </Typography.Paragraph>
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
    </Card>
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
  const { t } = useI18n();
  return (
    <div className="dns-value-row">
      <Typography.Text type="secondary">{label}</Typography.Text>
      <Typography.Paragraph code copyable className="dns-code-block">
        {value}
      </Typography.Paragraph>
      <Tooltip title={`${t('dnsRecord.copyLabel')}${label}`}>
        <Button icon={<CopyOutlined />} onClick={() => onCopy(value)} aria-label={`${t('dnsRecord.copyLabel')}${label}`} />
      </Tooltip>
    </div>
  );
}
