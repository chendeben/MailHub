import assert from 'node:assert/strict';
import { test } from 'node:test';

import { startTrackingRetentionWorker } from '../src/tracking-retention.js';

test('retention worker prunes on startup and interval and stops cleanly', async () => {
  const calls = [];
  const worker = startTrackingRetentionWorker({
    enabled: true,
    days: 45,
    intervalMs: 10,
    prune(options) {
      calls.push(options.days);
      return 1;
    },
    logger: { warn() {} }
  });

  await waitFor(() => calls.length >= 2);
  assert.deepEqual(calls.slice(0, 2), [45, 45]);
  worker.stop();
  const stoppedAt = calls.length;
  await new Promise((resolve) => setTimeout(resolve, 30));
  assert.equal(calls.length, stoppedAt);
});

test('retention worker can be disabled', () => {
  let calls = 0;
  const worker = startTrackingRetentionWorker({
    enabled: false,
    prune() {
      calls += 1;
    }
  });
  assert.equal(worker, null);
  assert.equal(calls, 0);
});

async function waitFor(predicate, timeoutMs = 500) {
  const startedAt = Date.now();
  while (!predicate()) {
    if (Date.now() - startedAt > timeoutMs) throw new Error('Timed out waiting for retention worker.');
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}
