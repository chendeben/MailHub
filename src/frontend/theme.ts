import type { ThemeConfig } from 'antd';

export const brandColors = {
  primary: '#4F46E5',
  primaryHover: '#4338CA',
  primarySoft: '#EEF2FF',
  ink: '#0F172A',
  textSecondary: '#64748B',
  textMuted: '#94A3B8',
  canvas: '#F4F6FB',
  surface: '#FFFFFF',
  border: '#E2E8F0',
  success: '#16A34A',
  warning: '#D97706',
  danger: '#DC2626',
  chartPrimary: '#4F46E5',
  chartSuccess: '#16A34A',
  chartDanger: '#DC2626',
  chartWarning: '#D97706',
  chartTrack: '#DBEAFE'
} as const;

export const mailhubTheme: ThemeConfig = {
  token: {
    colorPrimary: brandColors.primary,
    colorSuccess: brandColors.success,
    colorWarning: brandColors.warning,
    colorError: brandColors.danger,
    colorBgLayout: brandColors.canvas,
    colorBgContainer: brandColors.surface,
    colorBorderSecondary: brandColors.border,
    colorText: brandColors.ink,
    colorTextSecondary: brandColors.textSecondary,
    borderRadius: 10,
    borderRadiusLG: 14,
    fontFamily:
      'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'
  },
  components: {
    Card: {
      borderRadiusLG: 14
    },
    Table: {
      cellPaddingBlock: 14,
      cellPaddingInline: 16
    },
    Button: {
      controlHeight: 36,
      borderRadius: 10
    },
    Menu: {
      darkItemBg: brandColors.ink,
      darkSubMenuItemBg: brandColors.ink,
      darkItemSelectedBg: 'rgba(79, 70, 229, 0.22)',
      darkItemSelectedColor: '#E0E7FF',
      darkItemHoverBg: 'rgba(255, 255, 255, 0.06)',
      itemBorderRadius: 10
    }
  }
};
