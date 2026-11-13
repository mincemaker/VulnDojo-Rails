import { mkdir } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { chromium } from 'playwright-core';
import { test, expect } from 'e2e';

for (const { mode, port, sameSite } of [
  { mode: 'SAFE', port: 3108, sameSite: 'Lax' },
  { mode: 'VULN', port: 3107, sameSite: 'None' },
]) {
  test(`${mode}: cross-site form POST ${mode === 'SAFE' ? 'cannot' : 'can'} create the victim's task`, async () => {
    const browser = await chromium.launch();
    // Only this test context accepts the local self-signed TLS certificate; SameSite and CSRF remain enabled.
    const context = await browser.newContext({ ignoreHTTPSErrors: true });
    await context.tracing.start({ screenshots: true, snapshots: true });
    let attacker: Server | undefined;
    try {
      const page = await context.newPage();
      const baseUrl = `https://localhost:${port}`;
      const name = `csrf-${randomUUID()}`;
      const email = `${name}@example.com`;
      const password = randomUUID();
      const attackTitle = `CSRF attack ${name}`;
      await page.goto(`${baseUrl}/signup`);
      await page.getByLabel('名前', { exact: true }).fill(name);
      await page.getByLabel('メールアドレス', { exact: true }).fill(email);
      await page.getByLabel('パスワード', { exact: true }).fill(password);
      await page.getByLabel('パスワード（確認）', { exact: true }).fill(password);
      await page.getByRole('button', { name: '登録する', exact: true }).click();
      await page.waitForURL(`${baseUrl}/tasks`);
      await page.getByRole('button', { name: 'ログアウト', exact: true }).click();
      await page.waitForURL(`${baseUrl}/login`);
      await page.getByLabel('メールアドレス', { exact: true }).fill(email);
      await page.getByLabel('パスワード', { exact: true }).fill(password);
      await page.getByRole('button', { name: 'ログイン', exact: true }).click();
      await page.waitForURL(`${baseUrl}/tasks`);

      const session = (await context.cookies(baseUrl)).find(cookie => cookie.name === '_session_id');
      expect(session?.sameSite).toBe(sameSite);
      expect(session?.httpOnly).toBe(true);
      if (mode === 'VULN') expect(session?.secure).toBe(true);

      await page.goto(`${baseUrl}/tasks/new`);
      await page.getByLabel('タイトル', { exact: true }).fill(`Legitimate ${name}`);
      await page.getByRole('button', { name: '保存', exact: true }).click();
      await page.waitForURL(/\/tasks\/\d+$/);
      expect(await page.locator('body').innerText()).toContain(`Legitimate ${name}`);

      // A real HTTP server on 127.0.0.1, so the attacker document is a different site from localhost.
      attacker = createServer((_, response) => {
        response.writeHead(200, { 'content-type': 'text/html' });
        response.end(`<!doctype html><form action="${baseUrl}/tasks" method="post"><input name="task[title]" value="${attackTitle}"><button>Submit attack</button></form>`);
      });
      await new Promise<void>(resolve => attacker!.listen(0, '127.0.0.1', resolve));
      const attackerOrigin = `http://127.0.0.1:${(attacker.address() as AddressInfo).port}`;
      await page.goto(`${attackerOrigin}/attack.html`);
      const submitted = page.waitForRequest(request => request.url() === `${baseUrl}/tasks` && request.method() === 'POST');
      const answered = page.waitForResponse(response => response.url() === `${baseUrl}/tasks`);
      await page.getByRole('button', { name: 'Submit attack', exact: true }).click();
      const request = await submitted;
      const response = await answered;
      const headers = await request.allHeaders();
      expect(headers.origin).toBe(attackerOrigin);
      expect(headers['sec-fetch-site']).toBe('cross-site');
      expect(headers.cookie?.includes('_session_id=') ?? false).toBe(mode === 'VULN');
      expect(request.postData()?.includes('authenticity_token')).toBe(false);
      console.info(JSON.stringify({ mode, chromium: browser.version(), sameSite: session?.sameSite,
        origin: headers.origin, secFetchSite: headers['sec-fetch-site'], sessionSent: !!headers.cookie,
        status: response.status() }));

      if (mode === 'SAFE') {
        // Without the session cookie Rails rejects the request at the CSRF check, before require_login.
        expect(response.status()).toBe(422);
      } else {
        expect(response.status()).toBe(302);
        await page.waitForURL(/\/tasks\/\d+$/);
        expect(await page.locator('body').innerText()).toContain(attackTitle);
        expect(await page.locator('body').innerText()).toContain(name);
      }
      await page.goto(`${baseUrl}/tasks`);
      expect(await page.getByText(attackTitle, { exact: true }).count()).toBe(mode === 'VULN' ? 1 : 0);
    } finally {
      await mkdir('.e2e/logs', { recursive: true });
      await context.tracing.stop({ path: `.e2e/logs/csrf-${mode.toLowerCase()}.zip` });
      await browser.close();
      attacker?.closeAllConnections();
      attacker?.close();
    }
  });
}
