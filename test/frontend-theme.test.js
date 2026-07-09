import test from 'node:test';
import assert from 'node:assert/strict';
import { mailhubTheme, brandColors } from '../src/frontend/theme.ts';

test('brand primary is indigo, not Ant Design default blue', () => {
  assert.equal(brandColors.primary, '#4F46E5');
  assert.notEqual(brandColors.primary.toLowerCase(), '#1677ff');
  assert.equal(mailhubTheme.token.colorPrimary, brandColors.primary);
});

test('layout canvas and ink tokens match redesign spec', () => {
  assert.equal(brandColors.canvas, '#F4F6FB');
  assert.equal(brandColors.ink, '#0F172A');
  assert.equal(mailhubTheme.token.colorBgLayout, brandColors.canvas);
});
