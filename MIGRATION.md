# Migration to e2e

Source: Ferrum/Minitest, `test/integration/vulnerabilities/*_browser_test.rb`. Partial mapping via Selenium guide: https://e2e.tester.army/docs/migrate/selenium.md; engine: https://e2e.tester.army/docs/web.md.
e2e: `e2e.config.ts`, tests `tests/**/*.e2e.ts`, excluding the scaffold `tests/example.e2e.ts`.
Start dependencies: `docker compose up -d redis`
Run old: `docker compose run --rm -e RAILS_ENV=test -e VULN_CHALLENGES= web bundle exec rake test`
Run new: `docker compose -f compose.yaml -f compose.e2e.yaml run --rm e2e npx e2e run`
Harness: done, smoke `tests/css-injection.e2e.ts` on Chromium in Docker.
Status: complete for the Ferrum browser suite; all ten tests ported and all four source files retired with user approval.
Defect check: off; no planted defect was authorized or used.

## Browser inventory

| Source | e2e | Status | Assertions (source → e2e) | Passing | Defect check | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| css_injection_browser_test.rb | tests/css-injection.e2e.ts | retired | 4 → 5 | Chromium 3/3 per test | not run | 2 tests; user approved deletion after parity proof |
| xss_raw_browser_test.rb | tests/xss-raw.e2e.ts | retired | 4 → 5 | Chromium 3/3 per test | not run | 2 tests; user approved deletion after parity proof |
| csp_disable_browser_test.rb | tests/csp-disable.e2e.ts | retired | 4 → 8 | Chromium 3/3 per test | not run | 2 tests; user approved deletion; adds DOM presence and image completion checks |
| xss_stored_img_browser_test.rb | tests/xss-stored-img.e2e.ts | retired | 8 → 13 | Chromium 3/3 per test | not run | 4 tests; user approved deletion; image helper extracted unchanged |

This migration covers the Ferrum browser suite only. HTTP and other Minitest tests remain outside its scope. Initial Minitest runtime collection reported 10 browser tests across four files, without skips or browser branches, with 20 assertions. All four source files are now retired with user approval. e2e has ten tests with 31 assertions covering every source assertion. No CI workflow exists in this repository; README.md and CLAUDE.md document the runner commands.

## Docker setup and validation

The e2e image adds Node 24 to the existing development image. Its dependencies and Chromium use named Docker volumes, keeping host node_modules separate. Prepare test and development databases as documented in README.md before running the old suite.

- Build: `docker compose -f compose.yaml -f compose.e2e.yaml build e2e`
- Install dependencies: `docker compose -f compose.yaml -f compose.e2e.yaml run --rm e2e npm ci`
- Install browser: `docker compose -f compose.yaml -f compose.e2e.yaml run --rm e2e npx @e2e-dev/web install chromium`
- Collect: `docker compose -f compose.yaml -f compose.e2e.yaml run --rm e2e npx e2e list`
- Proof: `docker compose -f compose.yaml -f compose.e2e.yaml run --rm e2e npx e2e run tests/css-injection.e2e.ts --repeat-each 3 --retries 0` — 6/6 passed.
- Combined proof: `docker compose -f compose.yaml -f compose.e2e.yaml run --rm e2e npx e2e run --repeat-each 3 --retries 0` — 30/30 passed, ten tests each 3/3 on Chromium.

Final post-retirement validation: e2e 30/30 passed after extracting ImageTaskHelper; remaining Minitest suite 105 tests and 260 assertions, 0 failures, errors, or skips. Both runners executed sequentially in Docker. The retired source files have no remaining executable consumers.

Before final retirement, the full source suite passed 113 tests and 276 assertions, with no failures, errors, or skips. SSRF passed on the first attempt in that run. The source XSS raw file also passed independently: 2 tests, 4 assertions. Both suites run in Docker sequentially.

CSP slice validation: source CSP passed 2/2 with 4 assertions; all remaining source browser tests passed 8/8 with 16 assertions. The full old suite was not rerun for this slice because no source, application, or old-runner code changed. CSP's negative check runs after the injected image exists and its load completes; the positive check polls the execution flag.

Image slice validation: source image XSS passed 4/4 with 8 assertions; all remaining source browser tests passed 8/8 with 16 assertions. No source tests, helpers, or application code changed. The full old suite remains as verified before; this slice reran the affected browser suite only.

All commands above were executed. Run old: 115 tests, 279 assertions, 1 failure, 0 errors or skips. The failure is `SsrfTest#test_VULN:_leaks_session_data_from_Redis_via_gopher`: no Redis session keys found. An isolated rerun passed with 3 assertions. The user confirmed this test has a known timing issue. This is outside the migrated browser slice; no app or source test changes were made to bypass it.

The complete old Ferrum browser suite also passed sequentially in the new Docker image: 10 tests, 20 assertions, 0 failures, errors, or skips. A concurrent diagnostic run interfered with generated views; the sequential rerun above is the valid comparison.

## Shared helpers

| Source | e2e | Used by |
| --- | --- | --- |
| e2e_helper.rb ServerProcess, setup_session, create_task_via_form | tests/support/rails.rb reuses Ruby code unchanged; tests/support/rails-task.ts invokes it with task parameters | CSS injection, XSS raw, CSP |
| browser_helper.rb browser_login | browser.setCookies with the Ruby helper's session | CSS injection, XSS raw, CSP |
| xss_stored_img_browser_test.rb create_image_task_with_description | tests/support/image-task.rb ImageTaskHelper, invoked by tests/support/rails-task.ts createImageTask | Stored image XSS |

The data helper invokes existing Ruby HTTP helpers without booting Rails. Each server boots in a temporary app copy because each Rails boot clears generated vulnerability templates. The copies share the Docker storage volume but have independent generated views, logs, and temporary files. The harness starts servers sequentially using the source readiness check and removes the copies on exit. Do not run the two suites concurrently: they still share database storage.

Image setup uses the extracted ImageTaskHelper directly without booting Rails or loading any source test class. browser_helper.rb was removed after its three remaining consumers were retired. The existing HTTP e2e_helper.rb remains shared with Minitest. Ferrum's Gemfile entry is outside this approved cleanup and remains unchanged.

## Gaps

- Ferrum has no dedicated migration guide; Selenium's WebDriver mapping is applied to equivalent CDP operations.
- The existing example test is excluded from discovery. The existing model configuration is retained; this deterministic port makes no model calls.

## Next

Browser migration complete. User-approved image helper extraction and final source retirement are implemented and verified: e2e 30/30 and remaining Minitest 105/105 with 260 assertions. Image ports were committed as 1ad0b99. No source browser tests remain or stay behind. HTTP and other Minitest tests remain outside this migration; there is no next browser slice.
