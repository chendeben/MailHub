import type { ReactNode } from 'react';
import { Card } from 'antd';

export function SectionCard({
  title,
  extra,
  children,
  className
}: {
  title?: ReactNode;
  extra?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  const classes = ['section-card', className].filter(Boolean).join(' ');

  return (
    <Card title={title} extra={extra} className={classes}>
      {children}
    </Card>
  );
}
