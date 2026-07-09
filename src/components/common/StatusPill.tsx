import type { ReactNode } from 'react';

export type StatusTone = 'success' | 'warning' | 'error' | 'info' | 'neutral';

export function StatusPill({
  tone = 'neutral',
  icon,
  children
}: {
  tone?: StatusTone;
  icon?: ReactNode;
  children: ReactNode;
}) {
  return (
    <span className={`status-pill status-pill--${tone}`}>
      {icon}
      <span>{children}</span>
    </span>
  );
}
