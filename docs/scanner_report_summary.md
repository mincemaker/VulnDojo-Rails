# Scanner Report Summary — VulnDojo-Rails

Branch: `scanner-test/all-vulns` (vulnerabilities baked into `app/` source files)
Date: 2026-10-26

## Scanners

| Scanner | Version | Command |
|---------|---------|---------|
| Brakeman | 8.1.0 | `brakeman --run-all-checks --no-pager` |
| Foxguard | 0.14.1 | `npx foxguard .` |
| Semgrep (p/ruby) | 1.181.1 | `semgrep scan --config p/ruby .` (44 Ruby rules) |
| Semgrep (p/brakeman) | 1.181.1 | `semgrep scan --config p/brakeman .` (18 rules, Brakeman port) |
| Semgrep (p/default) | 1.181.1 | `semgrep scan --config p/default .` (349 rules, multi-language) |
| **Semgrep (custom)** | 1.181.1 | 11 custom rules targeting undetected patterns |

> 注: Brakeman は ghcr.io のイメージが取得できず、`bin/scan-scanners` のフォールバック（`docker compose run web` で `gem install brakeman`）で実行した。

## Detection by Challenge

| # | Challenge | Brakeman | Foxguard | Semgrep (std) | Custom Semgrep | Notes |
|---|-----------|:--------:|:--------:|:-------------:|:--------------:|-------|
| 1 | xss_raw | ❌ | ❌ | ✅ | ✅ | p/default `avoid-html-safe` が `_task_title.html.erb` の `.html_safe` を検出（旧版は未検出） |
| 2 | xss_stored_img | ❌ | ❌ | ✅ | ✅ | p/default `avoid-html-safe` / `var-in-href` が `_task_attachment.html.erb` を検出（旧版は未検出） |
| 3 | xss_reflected | ✅ High | ❌ | ✅ | ❌ | Brakeman `CrossSiteScripting`、p/default `alias-for-html-safe` が `<%==` を検出 |
| 4 | sql_injection | ✅ High | ✅ Critical | ✅ | ❌ | 3者とも WHERE の文字列補間を検出 |
| 5 | sql_injection_active_record | ❌ | ❌ | ❌ | ✅ | `Model.from(@view_type)` — 標準チェックなし |
| 6 | sql_injection_order | ✅ High | ✅ Critical | ❌ | ❌ | `lib/` の動的注入側のみで検出（`app/` には焼き込まれていない） |
| 7 | csrf_skip | ❌ | ❌ | ✅ | ✅ | p/default `rails-skip-forgery-protection` / `missing-csrf-protection`（旧版は未検出） |
| 8 | csp_disable | ❌ | ❌ | ❌ | ✅ | `script_src(:self, :unsafe_inline)` — カスタムルールのみ |
| 9 | command_injection | ✅ High | ✅ Critical | ✅ | ❌ | 3者とも backtick/subshell を検出 |
| 10 | idor | ✅ Weak | ❌ | ✅ | ❌ | Brakeman+Semgrep: `Task.find(params[:id])` の `UnscopedFind` |
| 11 | mass_assignment | ✅ Medium | ✅ High | ❌ | ❌ | 両者とも `permit!` を検出 |
| 12 | open_redirect | ❌ | ✅ High | ❌ | ✅ | Foxguard + カスタム: `allow_other_host: true` |
| 13 | regex_bypass | ✅ High | ❌ | ✅ | ❌ | Brakeman+Semgrep: バリデーション regex の `\A` vs `^` |
| 14 | ssrf | ❌ | ❌ | ✅ | ❌ | Semgrep `dangerous-exec` が `Open3.capture3("curl...")` を検出 |
| 15 | xxe_nokogiri | ❌ | ❌ | ❌ | ✅ | `Nokogiri::XML` + `config.noent` — 標準チェックなし |
| 16 | header_removal | ❌ | ❌ | ❌ | ✅ | `response.headers.delete(...)` — セキュリティヘッダ削除 |
| 17 | unsafe_file_upload | ❌ | ❌ | ❌ | ❌ | **未検出** — 空の `acceptable_attachment` バリデーション |
| 18 | log_leakage | ❌ | ❌ | ❌ | ✅ | `filter_parameters.clear` — パラメータフィルタ解除 |
| 19 | session_fixation | ❌ | ❌ | ❌ | ✅ | `reset_session` の欠落 |
| 20 | broken_auth_timing | ❌ | ❌ | ❌ | ❌ | **未検出** — 早期 return による bcrypt スキップ（タイミング差） |
| 21 | css_injection | ❌ | ❌ | ❌ | ✅ | `style` 属性への ERB 式埋め込み — 標準チェックなし |

## Totals

| Scanner | Detected | Missed | Detection Rate |
|---------|:--------:|:------:|:--------------:|
| Brakeman | 7 | 14 | 33% |
| Foxguard | 5 | 16 | 24% |
| Semgrep (standard rulesets) | 9 | 12 | 43% |
| **All standard scanners combined** | **12** | **9** | **57%** |
| **Custom Semgrep rules (11 rules)** | **11** | **10** | **52%** |
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

> `detect-html-safe` と `detect-csrf-skip` が狙う xss_raw / xss_stored_img / csrf_skip は、
> 今回のバージョンでは標準の p/default でも検出されるようになった。カスタムルールの固有の価値は
> csp_disable・sql_injection_active_record・xxe_nokogiri・header_removal・log_leakage・session_fixation・css_injection の 7 件に移った。

## Remaining Undetected (2)

| Challenge | Reason |
|-----------|--------|
| **unsafe_file_upload** (17) | 空の `acceptable_attachment` メソッド — バリデーションロジックの「不在」が脆弱性のため、意図的に寛容なコードと区別できずパターンマッチ不可。 |
| **broken_auth_timing** (20) | クロスプロシージャなタイミング攻撃 — `User.find_by` + 早期 return が定数時間認証を回避していることの理解が必要で、意味解析を要する。 |

## Key Findings

1. **標準スキャナー合計が 52% → 57% に上昇。** Semgrep の p/default が 182 → 349 ルールに増え、`avoid-html-safe` / `alias-for-html-safe` / `rails-skip-forgery-protection` が追加された。これにより xss_raw・xss_stored_img・xss_reflected・csrf_skip が標準ルールで検出されるようになった。

2. **カスタムルール込みの総合検出率は 90%（19/21）で前回と不変。** 標準の改善で xss_raw / xss_stored_img / csrf_skip が標準側に移ったが、同じチャレンジを別経路で押さえているため総合は変わらない。

3. **2 カテゴリは依然として不可視:**
   - 不在系の脆弱性: バリデーションの欠落（unsafe_file_upload）、定数時間比較の欠落（broken_auth_timing）
   - いずれもパターンマッチを超えた意味解析・クロスプロシージャ解析を要する

4. **誤検知（False Positive）:**
   - `detect-css-injection` が `_task_title.html.erb` と `index.html.erb` で発火。これらは hex カラーを `.match?()` で検証済みのため FP
   - `detect-session-fixation` が `users_controller.rb` で発火するが、ここでは `reset_session` が呼ばれているため FP（代入のみを見ている）
   - `detect-open-redirect` が `docs/` のコード例やログファイルでも発火
   - Brakeman / Semgrep の `reverse-tabnabbing` が `show.html.erb` で発火するが、`rel: "noopener noreferrer"` があるため FP

5. **Semgrep `dangerous-exec` が ssrf を単独検出** — `Open3.capture3("curl...")` に対して発火し、Brakeman・Foxguard では捉えられていない。
