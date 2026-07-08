import { Badge, Tag } from 'antd';

import { getRecordStatusMeta } from '../../frontend/domain-model.js';
import { useI18n } from '../../frontend/i18n/react';

interface StatusTagProps {
  status?: string;
  record?: { status?: string };
  label?: string;
  mode?: 'tag' | 'badge';
}

export function StatusTag({ status, record, label, mode = 'tag' }: StatusTagProps) {
  const { t } = useI18n();
  const meta = getRecordStatusMeta(record || { status });
  const text = label || t(`status.${meta.key}`);

  if (mode === 'badge') {
    return <Badge status={meta.color === 'default' ? 'default' : meta.color} text={text} />;
  }

  return <Tag color={meta.color}>{text}</Tag>;
}
