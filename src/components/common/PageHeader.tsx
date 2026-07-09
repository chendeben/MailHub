import type { ReactNode } from 'react';
import { Typography } from 'antd';

export function PageHeader({
  title,
  subtitle,
  extra
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  extra?: ReactNode;
}) {
  return (
    <div className="page-header">
      <div className="page-header__text">
        <Typography.Title level={3} className="page-header__title">
          {title}
        </Typography.Title>
        {subtitle ? (
          <Typography.Text type="secondary" className="page-header__subtitle">
            {subtitle}
          </Typography.Text>
        ) : null}
      </div>
      {extra ? <div className="page-header__extra">{extra}</div> : null}
    </div>
  );
}
