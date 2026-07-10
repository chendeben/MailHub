import { pruneTrackingEvents } from './db.js';

const defaultIntervalMs = 24 * 60 * 60 * 1000;

export function startTrackingRetentionWorker({
  enabled = true,
  days = 180,
  intervalMs = defaultIntervalMs,
  prune = pruneTrackingEvents,
  logger = console
} = {}) {
  if (!enabled) return null;
  const run = () => {
    try {
      Promise.resolve(prune({ days })).catch((error) => {
        logger.warn?.(`Tracking retention cleanup failed: ${error.message}`);
      });
    } catch (error) {
      logger.warn?.(`Tracking retention cleanup failed: ${error.message}`);
    }
  };
  run();
  const timer = setInterval(run, Math.max(10, Number(intervalMs) || defaultIntervalMs));
  timer.unref?.();
  return {
    run,
    stop() {
      clearInterval(timer);
    }
  };
}
