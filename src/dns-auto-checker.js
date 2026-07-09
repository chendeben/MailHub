import { listDomainsForDnsAutoCheck, saveDomainStatus } from './db.js';
import { buildDnsGuide } from './dns-guide.js';

const defaultIntervalMs = 60000;
const defaultLimit = 25;

export function shouldAutoCheckDomain(domain, { now = new Date(), minIntervalMs = defaultIntervalMs } = {}) {
  const status = domain?.status || {};
  if (status.verified === true) return false;
  const checkedAt = Date.parse(status.checkedAt || '');
  if (!Number.isFinite(checkedAt)) return true;
  return now.getTime() - checkedAt >= minIntervalMs;
}

export async function runDnsAutoCheck({
  listDomains = listDomainsForDnsAutoCheck,
  buildGuide = buildDnsGuide,
  saveStatus = saveDomainStatus,
  logger = console,
  now = () => new Date(),
  minIntervalMs = defaultIntervalMs,
  limit = defaultLimit
} = {}) {
  const referenceTime = typeof now === 'function' ? now() : now;
  const domains = listDomains();
  const candidates = domains
    .filter((domain) => shouldAutoCheckDomain(domain, { now: referenceTime, minIntervalMs }))
    .slice(0, safePositiveInt(limit, defaultLimit));
  let checked = 0;
  let failed = 0;

  for (const domain of candidates) {
    try {
      const guide = await buildGuide(domain);
      saveStatus(domain.id, domain.userId, guide);
      checked += 1;
    } catch (error) {
      failed += 1;
      logger.warn?.(`DNS auto-check failed for ${domain.domain}: ${error.message}`);
    }
  }

  return {
    checked,
    failed,
    skipped: domains.length - candidates.length
  };
}

export function startDnsAutoChecker({
  enabled = true,
  intervalMs = defaultIntervalMs,
  limit = defaultLimit,
  logger = console
} = {}) {
  if (!enabled) return null;
  const state = {
    stopped: false,
    checking: false
  };
  const checkIntervalMs = safePositiveInt(intervalMs, defaultIntervalMs);

  async function poll() {
    if (state.stopped || state.checking) return;
    state.checking = true;
    try {
      await runDnsAutoCheck({
        minIntervalMs: checkIntervalMs,
        limit,
        logger
      });
    } finally {
      state.checking = false;
    }
  }

  const timer = setInterval(poll, checkIntervalMs);
  timer.unref?.();
  setTimeout(poll, 5000).unref?.();
  return {
    stop() {
      state.stopped = true;
      clearInterval(timer);
    },
    poll
  };
}

function safePositiveInt(value, fallback) {
  const number = Number(value);
  return Number.isFinite(number) && number > 0 ? Math.floor(number) : fallback;
}
