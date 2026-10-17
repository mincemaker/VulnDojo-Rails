# Migration to e2e

Source: Ferrum/Minitest, `test/integration/vulnerabilities/*_browser_test.rb`. Partial mapping via Selenium guide: https://e2e.tester.army/docs/migrate/selenium.md; engine: https://e2e.tester.army/docs/web.md.
e2e: `e2e.config.ts`, tests `tests/**/*.e2e.ts`.
Dependencies: Compose starts Redis automatically; the remaining SSRF Minitest tests need it.
Remaining Minitest: `docker compose run --rm -e RAILS_ENV=test -e VULN_CHALLENGES= web bundle exec rake test`
Run new: `docker compose -f compose.yaml -f compose.e2e.yaml run --rm e2e npx e2e run`
Harness: done, smoke `tests/css-injection.e2e.ts` on Chromium in Docker.
Status: complete for the Ferrum browser suite; all ten tests ported and all four source files retired with user approval.
Defect check: off; no planted defect was authorized or used.

## Browser inventory

| Source | e2e | Status | Assertions (source → e2e) | Passing | Defect check | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| css_injection_browser_test.rb | tests/css-injection.e2e.ts | retired | 4 → 6 | Chromium 3/3 per test | not run | 2 tests; user approved deletion after parity proof |
| xss_raw_browser_test.rb | tests/xss-raw.e2e.ts | retired | 4 → 6 | Chromium 3/3 per test | not run | 2 tests; user approved deletion after parity proof |
| csp_disable_browser_test.rb | tests/csp-disable.e2e.ts | retired | 4 → 8 | Chromium 3/3 per test | not run | 2 tests; user approved deletion; adds DOM presence and image completion checks |
| xss_stored_img_browser_test.rb | tests/xss-stored-img.e2e.ts | retired | 8 → 14 | Chromium 3/3 per test | not run | 4 tests; user approved deletion; image helper extracted |

This migration covers the Ferrum browser suite only. HTTP and other Minitest tests remain outside its scope. Initial Minitest runtime collection reported 10 browser tests across four files, without skips or browser branches, with 20 assertions. All four source files are retired with user approval. e2e has ten tests with 34 assertions covering every source assertion. No CI workflow exists in this repository; README.md and CLAUDE.md document the runner commands.

## Docker setup and validation

The e2e image adds Node 24 to the existing development image. Its dependencies and Chromium use named Docker volumes, keeping host node_modules separate. Prepare test and development databases as documented in README.md before running the old suite.

- Build: `docker compose -f compose.yaml -f compose.e2e.yaml build e2e`
- Install dependencies: `docker compose -f compose.yaml -f compose.e2e.yaml run --rm e2e npm ci`
- Install browser: `docker compose -f compose.yaml -f compose.e2e.yaml run --rm e2e npx @e2e-dev/web install chromium`
- Collect: `docker compose -f compose.yaml -f compose.e2e.yaml run --rm e2e npx e2e list`
- Proof: `docker compose -f compose.yaml -f compose.e2e.yaml run --rm e2e npx e2e run tests/css-injection.e2e.ts --repeat-each 3 --retries 0` — 6/6 passed.
- Combined proof: `docker compose -f compose.yaml -f compose.e2e.yaml run --rm e2e npx e2e run --repeat-each 3 --retries 0` — 30/30 passed, ten tests each 3/3 on Chromium.

Final review-fix validation: e2e 30/30 passed, ten tests each repeated three times with retries disabled; remaining Minitest 107 tests and 273 assertions, 0 failures, errors, or skips. Both runners executed sequentially in Docker. SSRF passed on the first attempt. The retired source files have no remaining executable consumers.

SAFE rendering checks were verified against a temporary HTTP 500 response: the old absence-only assertions passed all three tests, and the strengthened assertions failed all three at the missing page text. The response override was then removed. No application code was changed. The SSRF Minitest has a known timing issue; a failure must be reported and rerun rather than bypassed.

## Shared helpers

| Source | e2e | Used by |
| --- | --- | --- |
| e2e_helper.rb ServerProcess, setup_session, create_task_via_form | tests/support/rails.rb reuses Ruby code unchanged; tests/support/rails-task.ts invokes it with task parameters | CSS injection, XSS raw, CSP |
| browser_helper.rb browser_login | browser.setCookies with the Ruby helper's session | CSS injection, XSS raw, CSP |
| xss_stored_img_browser_test.rb create_image_task_with_description | tests/support/image-task.rb ImageTaskHelper, invoked by tests/support/rails-task.ts createImageTask | Stored image XSS |

The data helper invokes existing Ruby HTTP helpers without booting Rails. Each server boots in a temporary app copy because each Rails boot clears generated vulnerability templates. The copies share the Docker storage volume but have independent generated views, logs, and temporary files. The harness checks each child's exit status and health endpoint before starting the next server. It archives Rails and Puma logs under `.e2e/logs/` before removing the app copies. Do not run the two suites concurrently: they still share database storage.

Image setup uses the extracted ImageTaskHelper directly without booting Rails or loading any source test class. browser_helper.rb was removed after its three remaining consumers were retired. The existing HTTP e2e_helper.rb remains shared with Minitest. Ferrum's Gemfile entry is outside this approved cleanup and remains unchanged.

## Gaps

- Ferrum has no dedicated migration guide; Selenium's WebDriver mapping is applied to equivalent CDP operations.
- The existing model configuration is retained; these deterministic tests make no model calls or authentication requests.

## Skill setup

`apm.yml` and `apm.lock.yaml` pin both e2e and migrate-to-e2e skills for Claude Code and Codex. Run `apm install --frozen` on the host; generated `.agents/skills/` and `.claude/skills/` copies are ignored. npm dependencies and the test config are committed, so a checkout runs through `npm ci` and browser installation in Docker without `e2e init`. MCP setup is optional. Frozen APM installation was verified in an empty directory containing only the manifest and lockfile.

## Next

Browser migration complete. No source browser tests remain or stay behind. HTTP and other Minitest tests remain outside this migration; there is no next browser slice.
