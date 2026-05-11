# Scanner Report Summary — VulnDojo-Rails

Branch: `scanner-test/all-vulns` (vulnerabilities baked into `app/` source files)
Date: 2026-05-11

## Scanners

| Scanner | Version | Command |
|---------|---------|---------|
| Brakeman | 8.0.4 | `brakeman --run-all-checks --no-pager` (86 checks) |
| Foxguard | 0.8.0 | `npx foxguard .` |
| Semgrep (p/ruby) | 1.162.0 | `semgrep scan --config p/ruby .` (44 Ruby rules) |
| Semgrep (p/brakeman) | 1.162.0 | `semgrep scan --config p/brakeman .` (18 rules, Brakeman port) |
| Semgrep (p/default) | 1.162.0 | `semgrep scan --config p/default .` (182 rules, multi-language) |
| **Semgrep (custom)** | 1.162.0 | 11 custom rules targeting undetected patterns |

## Detection by Challenge

| # | Challenge | Brakeman | Foxguard | Semgrep (std) | Custom Semgrep | Notes |
|---|-----------|:--------:|:--------:|:-------------:|:--------------:|-------|
| 1 | xss_raw | ❌ | ❌ | ❌ | ✅ | `.html_safe` in ERB — Brakeman's XSS check only fires on `params[:q]` reflected, not model attr |
| 2 | xss_stored_img | ❌ | ❌ | ❌ | ✅ | `.html_safe` on `task.description` in ERB — same gap |
| 3 | xss_reflected | ✅ High | ❌ | ❌ | ❌ | Brakeman: `CrossSiteScripting` detects `params[:q]` via `<%==` |
| 4 | sql_injection | ✅ High | ✅ Critical | ✅ | ❌ | Brakeman, Foxguard, Semgrep all detect string interpolation in WHERE |
| 5 | sql_injection_active_record | ❌ | ❌ | ❌ | ✅ | `Model.from(@view_type)` — no standard check for Arel `from()` injection |
| 6 | sql_injection_order | ✅ High | ✅ Critical | ❌ | ❌ | Brakeman: `Arel.sql`; Foxguard: string interpolation in LIKE |
| 7 | csrf_skip | ❌ | ❌ | ❌ | ✅ | `skip_forgery_protection` — Brakeman's `ForgerySetting` didn't match |
| 8 | csp_disable | ❌ | ❌ | ❌ | ✅ | `script_src(:self, :unsafe_inline)` — absence vuln partially detectable |
| 9 | command_injection | ✅ High | ✅ Critical | ✅ | ❌ | All three detect backtick/Open3 injection |
| 10 | idor | ✅ Weak | ❌ | ✅ | ❌ | Brakeman+Semgrep: `UnscopedFind` on `Task.find(params[:id])` |
| 11 | mass_assignment | ✅ Medium | ✅ High | ❌ | ❌ | Both: `permit!` detection |
| 12 | open_redirect | ❌ | ✅ High | ❌ | ✅ | Foxguard + custom: `redirect_to` with `allow_other_host: true` |
| 13 | regex_bypass | ✅ High | ❌ | ✅ | ❌ | Brakeman+Semgrep: `\A` vs `^` in validation regex |
| 14 | ssrf | ❌ | ❌ | ✅ | ❌ | Semgrep `p/ruby`: `dangerous-exec` on `Open3.capture3("curl...")` |
| 15 | xxe_nokogiri | ❌ | ❌ | ❌ | ✅ | `Nokogiri::XML` with `config.noent` — no standard check exists |
| 16 | header_removal | ❌ | ❌ | ❌ | ✅ | `response.headers.delete(...)` — removes security headers |
| 17 | unsafe_file_upload | ❌ | ❌ | ❌ | ❌ | **STILL UNDETECTED** — empty `acceptable_attachment` validation |
| 18 | log_leakage | ❌ | ❌ | ❌ | ✅ | `filter_parameters.clear` — removes default parameter filtering |
| 19 | session_fixation | ❌ | ❌ | ❌ | ✅ | `session[:user_id] = user.id` without prior `reset_session` |
| 20 | broken_auth_timing | ❌ | ❌ | ❌ | ❌ | **STILL UNDETECTED** — timing attack via early return skips bcrypt |
| 21 | css_injection | ❌ | ❌ | ❌ | ✅ | ERB expression in `style` attribute — no standard check exists |

## Totals

| Scanner | Detected | Missed | Detection Rate |
|---------|:--------:|:------:|:--------------:|
| Brakeman | 7 | 14 | 33% |
| Foxguard | 6 | 15 | 29% |
| Semgrep (standard rulesets) | 3 | 18 | 14% |
| **All standard scanners combined** | **11** | **10** | **52%** |
| **Custom Semgrep rules (11 rules)** | **10** | **11** | **48%** |
| **All scanners + custom rules** | **19** | **2** | **90%** |

## Custom Semgrep Rules

11 custom rules created in `docs/custom_semgrep_rules.yml`:

| Rule ID | Pattern | Detects |
|---------|---------|---------|
| `detect-html-safe` | `.html_safe` in ERB files | xss_raw, xss_stored_img |
| `detect-csrf-skip` | `skip_forgery_protection` | csrf_skip |
| `detect-unsafe-inline-script` | `script_src(:self, :unsafe_inline)` | csp_disable |
| `detect-xxe-nokogiri` | `Nokogiri::XML { \|c\| c.noent }` | xxe_nokogiri |
| `detect-header-removal` | `response.headers.delete(...)` | header_removal |
| `detect-filter-parameters-clear` | `filter_parameters.clear` | log_leakage |
| `detect-arel-sql-from` | `Model.from(dynamic_arg)` | sql_injection_active_record |
| `detect-css-injection` | regex: `style="..." <%= ... %>` | css_injection |
| `detect-session-fixation` | regex: `session[:user_id] =` | session_fixation |
| `detect-open-redirect` | regex: `redirect_to var, allow_other_host: true` | open_redirect |
| `detect-arel-where-interpolation` | `where("... #{...} ...")` | (supplemental) |

## Remaining Undetected (2)

| Challenge | Reason |
|-----------|--------|
| **unsafe_file_upload** (17) | Empty `acceptable_attachment` method — pattern is "absence" of validation logic. Requires semantic understanding that the method body is empty. Hard to distinguish from intentionally-permissive code. |
| **broken_auth_timing** (20) | Cross-procedural timing attack: early return before bcrypt comparison in `SessionsController#create`. Requires understanding that `User.find_by` + early return bypasses constant-time authentication. |

## Key Findings

1. **Custom rules raise detection from 52% to 90%** — 10 of 12 previously-undetected challenges are now detectable with targeted patterns.

2. **Two categories remain invisible:**
   - **Absence vulnerabilities**: Missing validation (unsafe_file_upload), missing constant-time comparison (broken_auth_timing)
   - These require semantic/cross-procedural analysis beyond pattern matching

3. **False positives in custom rules:**
   - `detect-css-injection` fires on `_task_title.html.erb:7` and `index.html.erb:51` where ERB-in-style uses hex-color checked by `.match?()` — FP if the value is pre-validated
   - `detect-session-fixation` fires on `users_controller.rb:14` where `reset_session` IS called — the pattern only sees the assignment, not the prior call
   - `detect-open-redirect` fires on code examples in docs/ and log files

4. **Semgrep `p/ruby` uniquely detected ssrf** via `dangerous-exec` rule on `Open3.capture3` — not caught by Brakeman or Foxguard.

5. **Brakeman `Reverse Tabnabbing` finding in `show.html.erb:41`** was a false positive — the template has `rel: "noopener noreferrer"` present.
