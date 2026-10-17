// Ported from test/integration/vulnerabilities/csp_disable_browser_test.rb
import { test } from '@e2e-dev/web';
import { expect } from 'e2e';
import { createTask } from './support/rails-task.js';

const title = '<img src=x onerror="window.__xss=true">';

test('SAFE: CSP blocks inline event handler even when html_safe is active', async ({ app, browser }) => {
  const result = await createTask(3103, { title });
  expect(result.id).toBeTruthy();
  const [name, ...value] = result.cookie.split('=');
  await browser.setCookies([{ name, value: value.join('='), domain: '127.0.0.1', path: '/' }]);
  await app.open(`http://127.0.0.1:3103/tasks/${result.id}`);
  await expect(browser.locator('img[onerror]')).toBeAttached();
  await expect.poll(() => browser.evaluate(() =>
    (document.querySelector('img[onerror]') as HTMLImageElement).complete
  )).toBe(true);
  expect(await browser.evaluate('!!window.__xss')).toBe(false);
});

test('VULN: disabling CSP allows inline event handler to execute', async ({ app, browser }) => {
  const result = await createTask(3104, { title });
  expect(result.id).toBeTruthy();
  const [name, ...value] = result.cookie.split('=');
  await browser.setCookies([{ name, value: value.join('='), domain: '127.0.0.1', path: '/' }]);
  await app.open(`http://127.0.0.1:3104/tasks/${result.id}`);
  await expect(browser.locator('img[onerror]')).toBeAttached();
  await expect.poll(() => browser.evaluate(() =>
    (document.querySelector('img[onerror]') as HTMLImageElement).complete
  )).toBe(true);
  await expect.poll(() => browser.evaluate('!!window.__xss')).toBe(true);
});
