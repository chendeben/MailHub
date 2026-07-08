import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  buildApiUsageExamples,
  canCopyFullApiToken,
  formatApiTokenPrefix,
  getCopyableApiToken,
  getCreatedApiTokenSecret
} from '../src/frontend/api-token-model.js';

test('only exposes full API token when the create response includes the secret', () => {
  const created = { tokenPrefix: 'mh_123456789', token: 'mh_123456789.full-secret' };
  const listed = { tokenPrefix: 'mh_987654321' };

  assert.equal(canCopyFullApiToken(created), true);
  assert.equal(getCreatedApiTokenSecret(created), 'mh_123456789.full-secret');
  assert.equal(getCopyableApiToken(created), 'mh_123456789.full-secret');

  assert.equal(canCopyFullApiToken(listed), false);
  assert.equal(getCreatedApiTokenSecret(listed), '');
  assert.equal(getCopyableApiToken(listed), '');
});

test('formats token prefixes without pretending the full secret is available', () => {
  assert.equal(formatApiTokenPrefix({ tokenPrefix: 'mh_abcdef1234' }), 'mh_abcdef1234...');
  assert.equal(formatApiTokenPrefix({}), '-');
});

test('builds API usage examples with endpoint, bearer token, and message body', () => {
  const examples = buildApiUsageExamples({
    endpoint: 'https://mailhub.example.com/api/send',
    token: 'mh_example_token',
    from: 'noreply@example.com',
    to: 'user@example.com'
  });

  assert.match(examples.curl, /Authorization: Bearer mh_example_token/);
  assert.match(examples.curl, /https:\/\/mailhub\.example\.com\/api\/send/);
  assert.match(examples.nodeFetch, /fetch\('https:\/\/mailhub\.example\.com\/api\/send'/);
  assert.match(examples.nodeFetch, /from: 'noreply@example.com'/);
  assert.match(examples.requestBody, /"to": "user@example.com"/);
  assert.match(examples.successResponse, /"queued": true/);
});
