# tsubame-rails ドキュメント

セットアップ・起動方法・アーキテクチャはルートの [README.md](../README.md) を参照してください。
このディレクトリには、チャレンジのリファレンスと関連資料を置いています。

## ファイル一覧

- `README.md` — チャレンジリファレンス（このファイル）
- `rails_security_checklist.md` — Rails 7.1 セキュリティチェックリスト（安全な実装の根拠）

---

## チャレンジ一覧

| slug | タイトル | カテゴリ | 難易度 | CWE |
|------|---------|---------|-------|-----|
| `xss_raw` | Stored XSS via html_safe | xss | easy | CWE-79 |
| `sql_injection` | SQL Injection via search | injection | medium | CWE-89 |
| `csrf_skip` | CSRF protection disabled | csrf | easy | CWE-352 |
| `open_redirect` | Open Redirect via return_to | redirect | easy | CWE-601 |
| `idor` | IDOR — Insecure Direct Object Reference | authorization | easy | CWE-639 |
| `session_fixation` | Session Fixation — reset_session 無効化 | session | medium | CWE-384 |
| `mass_assignment` | Mass Assignment via permit! | authorization | medium | CWE-915 |
| `regex_bypass` | Regex Bypass — ^ vs \A anchor | validation | medium | CWE-185 |
| `unsafe_file_upload` | Unsafe File Upload — MIME validation disabled | upload | medium | CWE-434 |
| `log_leakage` | Log Leakage — parameter filter disabled | logging | easy | CWE-532 |
| `css_injection` | CSS Injection via style attribute | xss | medium | CWE-79 |
| `header_removal` | HTTP Security Headers Removed | headers | easy | CWE-693 |
| `csp_disable` | Content Security Policy Disabled | headers | easy | CWE-693 |
| `command_injection` | Command Injection via CSV export | injection | hard | CWE-78 |

---

## チャレンジ詳細

### xss_raw — Stored XSS via html_safe

```bash
VULN_CHALLENGES=xss_raw bin/rails server -b 127.0.0.1
```

タスクの `show` テンプレートが差し替えられ、タイトルが `@task.title.html_safe` で出力されます。
ERB の自動エスケープが無効になるため、タイトルに含まれた HTML タグがそのまま DOM に挿入されます。

再現手順:
1. タスクを新規作成し、タイトルに `<img src=x onerror="alert('XSS')">` を入力
2. タスク詳細ページを開くと img 要素が DOM に挿入される

> ベースアプリには CSP (`script-src: 'self'`) が設定されているため、インラインイベントハンドラ (`onerror` 等) の実行はブラウザによりブロックされます。JS を実際に実行させるには `csp_disable` と組み合わせてください。

```bash
VULN_CHALLENGES=xss_raw,csp_disable bin/rails server -b 127.0.0.1
```

検出ポイント: `lib/vulnerabilities/challenges/xss_raw.rb` — `@task.title.html_safe`

参考: https://guides.rubyonrails.org/security.html#cross-site-scripting-xss

---

### sql_injection — SQL Injection via search

```bash
VULN_CHALLENGES=sql_injection bin/rails server -b 127.0.0.1
```

タスク一覧に検索フォームが追加され、`index` アクションが以下のクエリを実行します。

```ruby
Task.where("title LIKE '%#{params[:q]}%'")
```

文字列補間によりユーザー入力がそのまま SQL に展開されます。

再現手順:
1. タスク一覧の検索ボックスに `' OR '1'='1` を入力
2. 他ユーザのタスクを含む全件が返される

検出ポイント: `lib/vulnerabilities/challenges/sql_injection.rb` — `where("title LIKE '%#{params[:q]}%'")`

参考: https://guides.rubyonrails.org/security.html#sql-injection

---

### csrf_skip — CSRF protection disabled

```bash
VULN_CHALLENGES=csrf_skip bin/rails server -b 127.0.0.1
```

`TasksController.skip_forgery_protection` が呼ばれ、CSRF トークン検証が無効化されます。
CSRF トークンなしの POST リクエストがそのまま処理されます。

再現手順:
1. curl でトークンなしの POST を送信してタスクを作成できることを確認

```bash
curl -X POST http://localhost:3000/tasks \
  -d "task[title]=injected" \
  -b "_session_id=<セッションID>"
```

検出ポイント: `lib/vulnerabilities/challenges/csrf_skip.rb` — `TasksController.skip_forgery_protection`

参考: https://guides.rubyonrails.org/security.html#cross-site-request-forgery-csrf

---

### open_redirect — Open Redirect via return_to

```bash
VULN_CHALLENGES=open_redirect bin/rails server -b 127.0.0.1
```

`ApplicationController#safe_redirect_to` が上書きされ、`return_to` パラメータの値を検証せずに `redirect_to` に渡します（`allow_other_host: true`）。
フィッシング攻撃などでユーザーを外部サイトへ誘導できます。

再現手順:
1. ブラウザで以下の URL を開く（ログイン後にリダイレクトされる）

```
http://localhost:3000/session/new?return_to=https://example.com
```

検出ポイント: `lib/vulnerabilities/challenges/open_redirect.rb` — `redirect_to url, allow_other_host: true`

参考: https://guides.rubyonrails.org/security.html#redirection

---

### idor — IDOR — Insecure Direct Object Reference

```bash
VULN_CHALLENGES=idor bin/rails server -b 127.0.0.1
```

`TasksController#set_task` が `current_user.tasks.find` から `Task.find` に差し替えられます。
所有者のスコープがなくなるため、任意のタスク ID を URL に指定すると他ユーザのタスクにアクセスできます。

再現手順:
1. ユーザー A でタスクを作成し、そのタスク ID を控える
2. 別のユーザー B でログインし、`/tasks/:id` に直接アクセス

検出ポイント: `lib/vulnerabilities/challenges/idor.rb` — `Task.find(params[:id])`（所有者スコープなし）

参考: https://guides.rubyonrails.org/security.html#unauthorized-viewing

---

### session_fixation — Session Fixation — reset_session 無効化

```bash
VULN_CHALLENGES=session_fixation bin/rails server -b 127.0.0.1
```

`SessionsController#create` が上書きされ、`reset_session` が呼ばれなくなります。
ログイン前後でセッション ID が変わらないため、攻撃者が事前にセッション ID をセットしておくと、被害者のログイン後もそのセッションを乗っ取れます。

再現手順:
1. ログイン前のセッション Cookie を記録
2. ログイン後に同じセッション Cookie が使われていることを確認

検出ポイント: `lib/vulnerabilities/challenges/session_fixation.rb` — `reset_session` の欠落

参考: https://guides.rubyonrails.org/security.html#session-fixation

---

### mass_assignment — Mass Assignment via permit!

```bash
VULN_CHALLENGES=mass_assignment bin/rails server -b 127.0.0.1
```

`task_params` が `params.require(:task).permit!` に差し替えられます。
全パラメータが許可されるため、`user_id` などの保護属性も変更できます。

再現手順:
1. タスク更新リクエストに `task[user_id]=2` を追加して送信
2. タスクの所有者が別ユーザーに変更される

検出ポイント: `lib/vulnerabilities/challenges/mass_assignment.rb` — `params.require(:task).permit!`

参考: https://guides.rubyonrails.org/security.html#mass-assignment

---

### regex_bypass — Regex Bypass — ^ vs \A anchor

```bash
VULN_CHALLENGES=regex_bypass bin/rails server -b 127.0.0.1
```

`Task` モデルの URL バリデーションが `\A` から `^` に差し替えられます。
`^` は行頭にマッチするため、改行に続く文字列がバリデーションをすり抜けます。

再現手順:
1. タスクの URL フィールドに以下を入力

```
http://legitimate.example
javascript:alert(1)
```

2. `^https?://` は最初の行にマッチするためバリデーションが通過する

検出ポイント: `lib/vulnerabilities/challenges/regex_bypass.rb` — `/^https?:\/\/.+/m`（`^` 使用）

参考: https://guides.rubyonrails.org/security.html#regular-expressions

---

### unsafe_file_upload — Unsafe File Upload — MIME validation disabled

```bash
VULN_CHALLENGES=unsafe_file_upload bin/rails server -b 127.0.0.1
```

`Task#acceptable_attachment` バリデーションメソッドが空のメソッドで上書きされます。
MIME タイプのホワイトリスト検証が無効化され、任意のファイルをアップロードできます。

再現手順:
1. タスクの添付ファイルとして `.sh` や `.exe` ファイルをアップロード
2. エラーなくアップロードが完了する

検出ポイント: `lib/vulnerabilities/challenges/unsafe_file_upload.rb` — `define_method(:acceptable_attachment) { }`

参考: https://guides.rubyonrails.org/security.html#file-uploads

---

### log_leakage — Log Leakage — parameter filter disabled

```bash
VULN_CHALLENGES=log_leakage bin/rails server -b 127.0.0.1
```

`Rails.application.config.filter_parameters` がクリアされます。
通常はフィルタされる `password`、`secret_note` などがログに平文で記録されます。

再現手順:
1. ログインまたはタスク作成を実行
2. `log/development.log` を確認するとパスワードが平文で記録されている

検出ポイント: `lib/vulnerabilities/challenges/log_leakage.rb` — `filter_parameters.clear`

参考: https://guides.rubyonrails.org/security.html#logging

---

### css_injection — CSS Injection via style attribute

```bash
VULN_CHALLENGES=css_injection bin/rails server -b 127.0.0.1
```

タスクの `show` テンプレートが差し替えられ、`@task.description` が `style` 属性に直接埋め込まれます。
CSS を使ったページ改ざんや、ブラウザによってはデータ窃取が可能になります。

再現手順:
1. タスクの説明に以下を入力して保存

```
background:red;position:fixed;top:0;left:0;width:100%;height:100%;z-index:9999
```

2. タスク詳細ページを開くとページ全体が赤く塗りつぶされる

検出ポイント: `lib/vulnerabilities/challenges/css_injection.rb` — `style="<%= @task.description %>"`

参考: https://guides.rubyonrails.org/security.html#css-injection

---

### header_removal — HTTP Security Headers Removed

```bash
VULN_CHALLENGES=header_removal bin/rails server -b 127.0.0.1
```

`Rails.application.config.action_dispatch.default_headers` が空ハッシュに設定されます。
`X-Frame-Options`、`X-Content-Type-Options`、`X-XSS-Protection` などのセキュリティヘッダが削除されます。

再現手順:
1. レスポンスヘッダを確認する

```bash
curl -I http://localhost:3000/tasks
```

2. `X-Frame-Options` 等のヘッダが存在しないことを確認

検出ポイント: `lib/vulnerabilities/challenges/header_removal.rb` — `default_headers = {}`

参考: https://guides.rubyonrails.org/security.html#default-headers

---

### csp_disable — Content Security Policy Disabled

```bash
VULN_CHALLENGES=csp_disable bin/rails server -b 127.0.0.1
```

`ApplicationController.content_security_policy(false)` が呼ばれ、CSP ヘッダが削除されます。
インラインスクリプトの実行制限がなくなり、XSS の影響が大きくなります。

再現手順:
1. レスポンスヘッダを確認する

```bash
curl -I http://localhost:3000/tasks
```

2. `Content-Security-Policy` ヘッダが存在しないことを確認

検出ポイント: `lib/vulnerabilities/challenges/csp_disable.rb` — `content_security_policy(false)`

参考: https://guides.rubyonrails.org/security.html#content-security-policy

---

### command_injection — Command Injection via CSV export

```bash
VULN_CHALLENGES=command_injection bin/rails server -b 127.0.0.1
```

`TasksController#export` が上書きされ、CSV ファイル名の生成にシェルコマンドが使われます。

```ruby
filename = `echo #{name}_#{Date.current.strftime('%Y%m%d')}.csv`
```

`name` パラメータがシェルに展開されるため、任意のコマンドを実行できます。

再現手順:
1. CSV エクスポートを以下の URL でリクエスト

```
GET /tasks/export?name=$(whoami)
```

2. レスポンスヘッダの `Content-Disposition` にコマンド実行結果が含まれる

検出ポイント: `lib/vulnerabilities/challenges/command_injection.rb` — `` `echo #{name}_...` ``

参考: https://guides.rubyonrails.org/security.html#command-line-injection
