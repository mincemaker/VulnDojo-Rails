// Ported from test/integration/vulnerabilities/xss_raw_browser_test.rb
import { test } from '@e2e-dev/web';
import { expect } from 'e2e';
import { createTask } from './support/rails-task.js';

const title = '<img src=x onerror="window.__xss=true">';

test('SAFE: XSS payload is escaped — no malicious img element in DOM', async ({ app, browser }) => {
  const result = await createTask(3101, { title });
  expect(result.id).toBeTruthy();
  const [name, ...value] = result.cookie.split('=');
  await browser.setCookies([{ name, value: value.join('='), domain: '127.0.0.1', path: '/' }]);
  await app.open(`http://127.0.0.1:3101/tasks/${result.id}`);
  await expect(browser).toHaveURL(`http://127.0.0.1:3101/tasks/${result.id}`);
  await expect(browser.locator('img[onerror]')).toHaveCount(0);
});

test('VULN: XSS payload is injected into DOM — malicious img element exists', async ({ app, browser }) => {
  const result = await createTask(3103, { title });
  expect(result.id).toBeTruthy();
  const [name, ...value] = result.cookie.split('=');
  await browser.setCookies([{ name, value: value.join('='), domain: '127.0.0.1', path: '/' }]);
  await app.open(`http://127.0.0.1:3103/tasks/${result.id}`);
  await expect(browser.locator('img[onerror]')).toBeAttached();
});
