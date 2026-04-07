# 📋 タスク管理 — 脆弱性診断学習プラットフォーム

Rails 製の CRUD アプリに、**環境変数ひとつで脆弱性を注入できる仕組み**を組み込んだ学習用プラットフォームです。

- ベースのアプリは [Rails セキュリティガイド](https://guides.rubyonrails.org/security.html) に準拠した安全な実装
- `VULN_CHALLENGES` 環境変数で、Ruby のメタプログラミング（`Module#prepend`、`prepend_view_path` 等）を使い脆弱性を動的に上書き注入
- 学習対象者に「どこに脆弱性があるか」を見つけさせる演習に使えます

## 技術スタック

| 項目 | 値 |
|------|-----|
| Ruby | 3.2.3 |
| Rails | 7.1.6 |
| DB | SQLite3 |
| サーバー | Puma |
| 認証 | bcrypt (`has_secure_password`) |
| ファイル添付 | Active Storage (Disk) |

---

## セットアップ

```bash
bundle install
bin/rails db:prepare
bin/rails db:seed   # デモユーザ作成: demo@example.com / password123
```

## 起動

```bash
# 安全な状態で起動（脆弱性なし）
bin/rails server -b 127.0.0.1

# 脆弱性を注入して起動
VULN_CHALLENGES=xss_raw,sql_injection,csrf_skip bin/rails server -b 127.0.0.1
```

ブラウザで http://localhost:3000 → ログイン画面へリダイレクトされます。
ダッシュボード http://localhost:3000/vulnerabilities で有効なチャレンジの状態を確認できます。

---

## 🛡️ ベースアプリのセキュリティ機能

ベースのアプリは脆弱性なしの安全な実装です。以下の対策が組み込まれています。

### 認証・セッション

| 対策 | 実装箇所 |
|------|----------|
| `has_secure_password` (bcrypt) | `User` モデル |
| ログイン/サインアップ時 `reset_session` | `SessionsController`, `UsersController` |
| `before_action :require_login` | `ApplicationController` |

### IDOR 防止（権限昇格防止）

```ruby
# 全アクションで所有者スコープ
@task = current_user.tasks.find(params[:id])
```

### 入力検証

| フィールド | バリデーション |
|----------|----------------|
| `title` | `presence: true` |
| `url` | `format: { with: /\Ahttps?:\/\/.+\z/ }` — `\A\z` アンカーで正規表現バイパス防止 |
| `attachment` | MIME ホワイトリスト + 10MB 上限 |
| `email` | 形式・一意性検証 |
| `password` | 8文字以上 |

### その他の対策

| 対策 | 説明 |
|------|------|
| Strong Parameters | 許可リスト方式 (`permit`) |
| CSRF 保護 | `protect_from_forgery` + `csrf_meta_tags` |
| 安全なリダイレクト | `safe_redirect_to`: 内部パスのみ許可 (`/` 始まり、`//` 非始まり) |
| ログフィルタリング | `secret_note` がログに `[FILTERED]` と表示 |
| CSV エクスポート | `CSV.generate` 使用（shell 不使用） |
| CSP ヘッダー | `config/initializers/content_security_policy.rb` |
| Host Authorization | `config.hosts` で localhost のみ許可 |
| セキュリティヘッダー | X-Frame-Options, X-Content-Type-Options 等 |

---

## 🔓 脆弱性診断学習機能

### アーキテクチャ

```
app/ (安全なコード)                    lib/vulnerabilities/ (注入レイヤー)
┌───────────────────────┐          ┌───────────────────────────────────┐
│ TasksController       │◄─prepend─┤ xss_raw / sql_injection /     │
│ SessionsController    │◄─prepend─┤ idor / mass_assignment /      │
│ ApplicationController │◄─prepend─┤ open_redirect / command_inj  │
│ Task (model)          │◄─eval────┤ regex_bypass/unsafe_upload   │
│ Config                │◄─config──┤ header_removal/csp_disable/  │
│                       │         │ log_leakage/session_fixation │
└───────────────────────┘          └───────────────────────────────────┘
```

`app/` 以下のコードには一切脆弱性がありません。
`lib/vulnerabilities/` の注入レイヤーが、起動時に安全なコードを**上書き**します。

### Ruby の仕組みの活用

| 手法 | 用途 | 使用チャレンジ |
|------|------|------|
| `Module#prepend` | コントローラのアクションメソッドを上書き | xss, sqli, idor, open_redirect, mass_assign, session_fix, cmd_inj |
| `prepend_view_path` | ビューテンプレートを脆弱版に差し替え | xss_raw, sql_injection, css_injection |
| `skip_forgery_protection` | クラスメソッド呼び出しで CSRF 無効化 | csrf_skip |
| `class_eval` | モデルのバリデーションを差し替え | regex_bypass, unsafe_file_upload |
| `config` 操作 | Rails 設定を変更 | header_removal, log_leakage, csp_disable |
| `Singleton` Registry | チャレンジの登録・有効化を一元管理 | 全チャレンジ |
| `to_prepare` callback | dev 環境のクラスリロード時にも再注入 | 全チャレンジ |

### 用意されているチャレンジ

| slug | 名前 | カテゴリ | 難易度 | CWE |
|------|------|---------|--------|-----|
| `xss_raw` | Stored XSS via html_safe | XSS | Easy | CWE-79 |
| `sql_injection` | SQL Injection via search | Injection | Medium | CWE-89 |
| `csrf_skip` | CSRF protection disabled | CSRF | Easy | CWE-352 |
| `open_redirect` | Open Redirect via return_to | Redirect | Easy | CWE-601 |
| `idor` | IDOR — Insecure Direct Object Reference | Authorization | Easy | CWE-639 |
| `session_fixation` | Session Fixation — reset_session 無効化 | Session | Medium | CWE-384 |
| `mass_assignment` | Mass Assignment via permit! | Authorization | Medium | CWE-915 |
| `regex_bypass` | Regex Bypass — ^ vs \\A anchor | Validation | Medium | CWE-185 |
| `unsafe_file_upload` | Unsafe File Upload — MIME validation disabled | Upload | Medium | CWE-434 |
| `log_leakage` | Log Leakage — parameter filter disabled | Logging | Easy | CWE-532 |
| `css_injection` | CSS Injection via style attribute | XSS | Medium | CWE-79 |
| `header_removal` | HTTP Security Headers Removed | Headers | Easy | CWE-693 |
| `csp_disable` | Content Security Policy Disabled | Headers | Easy | CWE-693 |
| `command_injection` | Command Injection via CSV export | Injection | Hard | CWE-78 |

### 使い方の例

```bash
# XSS だけ有効にして起動
VULN_CHALLENGES=xss_raw bin/rails server -b 127.0.0.1

# 複数同時に有効化
VULN_CHALLENGES=xss_raw,sql_injection bin/rails server -b 127.0.0.1

# 全部有効
VULN_CHALLENGES=xss_raw,sql_injection,csrf_skip,open_redirect,idor,session_fixation,mass_assignment,regex_bypass,unsafe_file_upload,log_leakage,css_injection,header_removal,csp_disable,command_injection bin/rails server -b 127.0.0.1
```

---

## 🧩 新しい脆弱性チャレンジの追加方法

### 1. チャレンジクラスを作成

`lib/vulnerabilities/challenges/` にファイルを追加します。

```ruby
# lib/vulnerabilities/challenges/open_redirect.rb
module Vulnerabilities
  module Challenges
    class OpenRedirect < Base
      metadata do
        name        "Open Redirect"
        category    :redirect
        difficulty  :medium
        description "リダイレクト先が検証されていません。"
        hint        "リダイレクト先のパラメータを確認してみましょう"
        cwe         "CWE-601"
        reference   "https://guides.rubyonrails.org/security.html#redirection"
      end

      def apply!
        vuln_module = Module.new do
          def create
            @task = current_user.tasks.build(task_params)
            if @task.save
              redirect_to params[:return_to] || @task  # ← 脆弱性: 未検証リダイレクト
            else
              render :new, status: :unprocessable_entity
            end
          end
        end
        prepend_to TasksController, vuln_module
      end
    end
  end
end
```

### 2. メタデータ DSL

| メソッド | 必須 | 説明 |
|---------|------|------|
| `name` | ○ | チャレンジの表示名 |
| `category` | ○ | カテゴリ（`:xss`, `:injection`, `:csrf` 等） |
| `difficulty` | ○ | 難易度（`:easy`, `:medium`, `:hard`） |
| `description` | ○ | 概要説明 |
| `hint` | | ヒント（複数回呼べる） |
| `cwe` | | CWE 番号 |
| `reference` | | 参考 URL |

### 3. 自動登録

ファイルを配置するだけで、起動時に `Vulnerabilities::Engine` が自動で読み込み・登録します。

```bash
VULN_CHALLENGES=open_redirect bin/rails server -b 127.0.0.1
```

slug はクラス名を `underscore` したもの（`OpenRedirect` → `open_redirect`）です。

---

## 🧪 テスト

### テストの実行

```bash
# 全テスト実行 (35テスト, 91アサーション)
bundle exec ruby -Itest -e "Dir['test/integration/vulnerabilities/*_test.rb'].each { |f| require File.expand_path(f) }"

# 個別実行
bundle exec ruby -Itest test/integration/vulnerabilities/xss_raw_test.rb
bundle exec ruby -Itest test/integration/vulnerabilities/idor_test.rb
# ... 他の *_test.rb も同様
```

### テストの仕組み

各テストは **別プロセスで Rails サーバーを2台起動**（SAFE 用 / VULN 用）し、`Net::HTTP` で HTTP リクエストを送って検証します。

```
 テストプロセス
    ├── ServerProcess (VULN_CHALLENGES="")           ← 安全なサーバー
    ├── ServerProcess (VULN_CHALLENGES="xss_raw")    ← 脆弱なサーバー
    └── Net::HTTP で両方にリクエスト → レスポンスを比較
```

テストヘルパー (`e2e_helper.rb`) がユーザーのサインアップ・ログイン・セッション Cookie 管理・タスク作成を自動化します。

### テスト一覧 (35テスト)

| チャレンジ | SAFEテスト | VULNテスト | ポート |
|-----------|------|------|------|
| xss_raw | XSSペイロードがエスケープされる | html_safeで生HTML出力 | 4010/4011 |
| sql_injection | 検索機能なし、q無視 | `' OR 1=1`で全件取得 + 検索UI注入 | 4020/4021 |
| csrf_skip | CSRFトークンなし→422 | トークンなしでタスク作成成功 | 4030/4031 |
| open_redirect | 外部URLの return_to 無視 | 外部URLへリダイレクト | 4040/4041 |
| idor | 他ユーザのタスクにアクセス不可 | Task.findで他ユーザのタスク閲覧可 | 4050/4051 |
| session_fixation | reset_sessionで新Cookie発行 | reset_sessionなしでログイン | 4060/4061 |
| mass_assignment | user_id変更不可 | permit!でuser_id上書き可能 | 4070/4071 |
| regex_bypass | 改行URLを\\Aで拒否 | ^で改行URLが通過 | 4080/4081 |
| unsafe_file_upload | exeファイル拒否 | MIME検証なしでexe通過 | 4090/4091 |
| log_leakage | secret_noteが[FILTERED] | パラメータフィルタ無効で平文記録 | 4100/4101 |
| css_injection | style属性に埋め込まない | descriptionがstyle属性に注入 | 4110/4111 |
| header_removal | X-Frame-Options等存在 | セキュリティヘッダ欠落 | 4120/4121 |
| csp_disable | CSPヘッダ存在 | CSP無効化 | 4130/4131 |
| command_injection | nameパラメータ無視 | \$(whoami)がファイル名に出現 | 4140/4141 |

### 新しいチャレンジのテスト追加方法

```ruby
# test/integration/vulnerabilities/open_redirect_test.rb
require "test_helper"
require_relative "e2e_helper"

class OpenRedirectTest < ActiveSupport::TestCase
  include E2EHelper

  setup do
    @safe_server = ServerProcess.new(port: 4040, vuln_challenges: "")
    @vuln_server = ServerProcess.new(port: 4041, vuln_challenges: "open_redirect")
    @safe_server.start!
    @vuln_server.start!
  end

  teardown do
    @safe_server.stop!
    @vuln_server.stop!
  end

  test "SAFE: redirect to external URL is blocked" do
    # ...
  end

  test "VULN: redirect to external URL succeeds" do
    # ...
  end
end
```

`E2EHelper` が提供するユーティリティ:

| メソッド | 説明 |
|---------|------|
| `ServerProcess.new(port:, vuln_challenges:)` | テスト用サーバーの定義 |
| `server.start!` / `server.stop!` | サーバーの起動・停止 |
| `server.get(path, headers:)` | HTTP GET リクエスト |
| `server.post(path, body:, headers:)` | HTTP POST リクエスト |
| `setup_session(server)` | ユーザー作成・ログインしてセッション Cookie を返す |
| `create_task_via_form(server, title:, cookie:)` | CSRF トークン付きでタスクを作成 |
| `extract_csrf_token(html)` | HTML からトークンを抽出 |
| `latest_cookie(response, fallback)` | レスポンスから最新のセッション Cookie を取得 |

---

## データモデル

### User

| フィールド | 型 | 説明 |
|----------|------|------|
| `name` | string | ユーザー名（一意） |
| `email` | string | メールアドレス（一意、小文字化） |
| `password_digest` | string | bcrypt ハッシュ |

### Task

| フィールド | 型 | 説明 |
|----------|------|------|
| `title` | string | タイトル（必須） |
| `description` | text | 説明 |
| `completed` | boolean | 完了フラグ |
| `due_date` | date | 期限 |
| `user_id` | integer | 所有者（外部キー） |
| `url` | string | 関連 URL |
| `secret_note` | text | 秘密メモ（ログフィルタリング対象） |
| `attachment` | Active Storage | 添付ファイル |

---

## ディレクトリ構成

```
tsubame-rails/
├── app/                                 # 安全なアプリケーションコード
│   ├── controllers/
│   │   ├── application_controller.rb     # 認証・安全リダイレクト
│   │   ├── sessions_controller.rb        # ログイン/ログアウト
│   │   ├── users_controller.rb           # ユーザー登録
│   │   ├── tasks_controller.rb           # CRUD + CSVエクスポート + 添付ファイル
│   │   └── vulnerabilities_controller.rb # ダッシュボード
│   ├── models/
│   │   ├── user.rb                       # has_secure_password
│   │   └── task.rb                       # バリデーション + Active Storage
│   └── views/
│       ├── layouts/application.html.erb  # ナビ + ログイン状態表示
│       ├── sessions/new.html.erb         # ログインフォーム
│       ├── users/new.html.erb            # サインアップフォーム
│       ├── tasks/                        # 安全なテンプレート
│       └── vulnerabilities/              # ダッシュボード
├── lib/vulnerabilities/                 # 脆弱性注入レイヤー
│   ├── base.rb                          # チャレンジ基底クラス + DSL
│   ├── registry.rb                      # Singleton レジストリ
│   ├── engine.rb                        # ブートローダー
│   ├── challenges/                      # 14個のチャレンジ実装
│   │   ├── xss_raw.rb               css_injection.rb
│   │   ├── sql_injection.rb          command_injection.rb
│   │   ├── csrf_skip.rb             open_redirect.rb
│   │   ├── idor.rb                  session_fixation.rb
│   │   ├── mass_assignment.rb        regex_bypass.rb
│   │   ├── unsafe_file_upload.rb     log_leakage.rb
│   │   └── header_removal.rb         csp_disable.rb
│   └── views/tasks/                     # 脆弱なテンプレート（注入用）
├── test/integration/vulnerabilities/     # E2E テスト (35テスト, 91アサーション)
│   ├── e2e_helper.rb                    # サーバー管理 + セッション管理
│   └── *_test.rb                        # 各チャレンジのE2Eテスト (14ファイル)
├── config/
│   ├── initializers/
│   │   ├── vulnerabilities.rb           # 注入の初期化
│   │   ├── content_security_policy.rb   # CSP ヘッダー
│   │   └── filter_parameter_logging.rb  # ログフィルタ (含 secret_note)
│   ├── storage.yml                      # Active Storage 設定
│   └── routes.rb                        # 認証 + CRUD + エクスポート
└── docs/
    └── rails_security_checklist.md       # Rails セキュリティガイド準拠チェックリスト
```

---

## セキュリティ

ベースのアプリは [Rails セキュリティガイド](https://guides.rubyonrails.org/security.html) に準拠して実装しています。
詳細は `docs/rails_security_checklist.md` を参照してください。
