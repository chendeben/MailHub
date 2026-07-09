import type { ReactNode } from 'react';
import { Card, Typography } from 'antd';

export function MetricCard({
  label,
  value,
  hint,
  tone = 'default'
}: {
  label: ReactNode;
  value: ReactNode;
  hint?: ReactNode;
  tone?: 'default' | 'warning' | 'danger';
}) {
  return (
    <Card className={`metric-card metric-card--${tone}`}>
      <Typography.Text type="secondary">{label}</Typography.Text>
      <Typography.Title level={3} className="metric-value">
        {value}
      </Typography.Title>
      {hint ? (
        <Typography.Text type="secondary" className="metric-card__hint">
          {hint}
        </Typography.Text>
      ) : null}
    </Card>
  );
}
