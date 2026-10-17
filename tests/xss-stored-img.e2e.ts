// Ported from test/integration/vulnerabilities/xss_stored_img_browser_test.rb
import { test } from '@e2e-dev/web';
import { expect } from 'e2e';
import { createImageTask } from './support/rails-task.js';

const description = '<img src=x onerror="window.__xss=true">';

test('SAFE: XSS payload in description is escaped — no malicious img element in DOM', async ({ app, browser }) => {
  const result = await createImageTask(3101, description);
  expect(result.id).toBeTruthy();
  const [name, ...value] = result.cookie.split('=');
  await browser.setCookies([{ name, value: value.join('='), domain: '127.0.0.1', path: '/' }]);
  await app.open(`http://127.0.0.1:3101/tasks/${result.id}`);
  await expect(browser).toHaveURL(`http://127.0.0.1:3101/tasks/${result.id}`);
  await expect(browser.locator('img[onerror]')).toHaveCount(0);
});

test('VULN: XSS payload in description is injected into DOM as malicious img element', async ({ app, browser }) => {
  const result = await createImageTask(3105, description);
  expect(result.id).toBeTruthy();
  const [name, ...value] = result.cookie.split('=');
  await browser.setCookies([{ name, value: value.join('='), domain: '127.0.0.1', path: '/' }]);
  await app.open(`http://127.0.0.1:3105/tasks/${result.id}`);
  await expect(browser.locator('img[onerror]')).toBeAttached();
});

test('SAFE: CSP blocks onerror execution even when XSS payload is in DOM', async ({ app, browser }) => {
  const result = await createImageTask(3105, description);
  expect(result.id).toBeTruthy();
  const [name, ...value] = result.cookie.split('=');
  await browser.setCookies([{ name, value: value.join('='), domain: '127.0.0.1', path: '/' }]);
  await app.open(`http://127.0.0.1:3105/tasks/${result.id}`);
  await expect(browser.locator('img[onerror]')).toBeAttached();
  await expect.poll(() => browser.evaluate(() =>
    (document.querySelector('img[onerror]') as HTMLImageElement).complete
  )).toBe(true);
  expect(await browser.evaluate('!!window.__xss')).toBe(false);
});

test('VULN: disabling CSP allows onerror to execute when XSS payload is in DOM', async ({ app, browser }) => {
  const result = await createImageTask(3106, description);
  expect(result.id).toBeTruthy();
  const [name, ...value] = result.cookie.split('=');
  await browser.setCookies([{ name, value: value.join('='), domain: '127.0.0.1', path: '/' }]);
  await app.open(`http://127.0.0.1:3106/tasks/${result.id}`);
  await expect(browser.locator('img[onerror]')).toBeAttached();
  await expect.poll(() => browser.evaluate(() =>
    (document.querySelector('img[onerror]') as HTMLImageElement).complete
  )).toBe(true);
  await expect.poll(() => browser.evaluate('!!window.__xss')).toBe(true);
});
