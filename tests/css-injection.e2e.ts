// Ported from test/integration/vulnerabilities/css_injection_browser_test.rb
// Vulnerabilities are baked into app/, so only the VULN behavior is asserted.
import { test } from '@e2e-dev/web';
import { expect } from 'e2e';
import { createTask } from './support/rails-task.js';

const task = { title: 'CSS test', color: 'red; background:blue' };

test('VULN: color CSS payload is applied as computed style in browser', async ({ app, browser }) => {
  const result = await createTask(3101, task);
  expect(result.id).toBeTruthy();
  const [name, ...value] = result.cookie.split('=');
  await browser.setCookies([{ name, value: value.join('='), domain: '127.0.0.1', path: '/' }]);
  await app.open(`http://127.0.0.1:3101/tasks/${result.id}`);
  await expect.poll(() => browser.evaluate(() =>
    getComputedStyle(document.getElementById('task-color-indicator')!).borderLeftColor
  )).toBe('rgb(255, 0, 0)');
});
