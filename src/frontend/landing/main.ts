import { detectLocale, setStoredLocale, supportedLocales, t } from './i18n.js';
import './landing.css';

let locale = detectLocale();

function applyLocale(next: string | null | undefined) {
  const resolved = next && supportedLocales.includes(next) ? next : 'en-US';
  locale = resolved;
  setStoredLocale(resolved);
  document.documentElement.lang = resolved === 'zh-CN' ? 'zh-CN' : 'en';

  document.querySelectorAll<HTMLElement>('[data-i18n]').forEach((el) => {
    const key = el.dataset.i18n;
    if (!key) return;
    el.textContent = t(resolved, key);
  });

  document.querySelectorAll<HTMLElement>('[data-i18n-html]').forEach((el) => {
    const key = el.dataset.i18nHtml;
    if (!key) return;
    el.innerHTML = t(resolved, key);
  });

  document.querySelectorAll<HTMLButtonElement>('.lang-btn').forEach((btn) => {
    btn.classList.toggle('is-active', btn.dataset.locale === resolved);
  });

  document.title = resolved === 'zh-CN' ? 'MailHub · 事务邮件平台' : 'MailHub · Transactional Email';
}

function setupLocaleSwitch() {
  document.querySelectorAll<HTMLButtonElement>('.lang-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const next = btn.dataset.locale || 'en-US';
      applyLocale(next);
    });
  });
}

function setupCopyButtons() {
  document.querySelectorAll<HTMLButtonElement>('.copy-btn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const targetId = btn.dataset.copyTarget;
      const node = targetId ? document.getElementById(targetId) : null;
      const text = node?.textContent || '';
      if (!text) return;
      try {
        await navigator.clipboard.writeText(text);
        const original = btn.textContent;
        btn.textContent = t(locale, 'common.copied');
        window.setTimeout(() => {
          btn.textContent = original || t(locale, 'common.copy');
        }, 1400);
      } catch {
        /* ignore */
      }
    });
  });
}

applyLocale(locale);
setupLocaleSwitch();
setupCopyButtons();
