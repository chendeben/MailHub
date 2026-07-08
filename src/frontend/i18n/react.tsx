import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';

import {
  DEFAULT_LOCALE,
  createTranslator,
  getLocaleLabel,
  normalizeLocale,
  supportedLocales
} from './index.js';

const storageKey = 'mailhub.locale';

interface I18nContextValue {
  locale: string;
  locales: Array<{ value: string; label: string }>;
  setLocale: (locale: string) => void;
  t: (key: string) => string;
}

const I18nContext = createContext<I18nContextValue | null>(null);

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState(() => initialLocale());

  useEffect(() => {
    document.documentElement.lang = locale;
    window.localStorage.setItem(storageKey, locale);
  }, [locale]);

  const value = useMemo<I18nContextValue>(() => ({
    locale,
    locales: supportedLocales.map((value) => ({ value, label: getLocaleLabel(value) })),
    setLocale: (nextLocale) => setLocaleState(normalizeLocale(nextLocale)),
    t: createTranslator(locale)
  }), [locale]);

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n() {
  const context = useContext(I18nContext);
  if (!context) throw new Error('useI18n must be used inside I18nProvider');
  return context;
}

function initialLocale() {
  if (typeof window === 'undefined') return DEFAULT_LOCALE;
  const params = new URLSearchParams(window.location.search);
  return normalizeLocale(params.get('lang') || window.localStorage.getItem(storageKey) || DEFAULT_LOCALE);
}
