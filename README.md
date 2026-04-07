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
app/ (安全なコード)              lib/vulnerabilities/ (注入レイヤー)
┌──────────────────┐            ┌──────────────────────────────┐
│ TasksController   │◄─ prepend ─┤ challenges/xss_raw.rb        │ html_safe でエスケープ無効化
│ (安全な実装)      │◄─ prepend ─┤ challenges/sql_injection.rb  │ 文字列補間 SQL + 検索 UI 注入
│                   │◄─ skip ────┤ challenges/csrf_skip.rb      │ CSRF 保護スキップ
└──────────────────┘            └──────────────────────────────┘

app/views/ (安全)                lib/vulnerabilities/views/ (脆弱)
┌──────────────────┐            ┌──────────────────────────────┐
│ tasks/show.erb    │◄─ prepend_view_path ─┤ tasks/show.erb    │
│ tasks/index.erb   │◄──────────────────┤ tasks/index.erb   │
└──────────────────┘            └──────────────────────────────┘
```

`app/` 以下のコードには一切脆弱性がありません。
`lib/vulnerabilities/` の注入レイヤーが、起動時に安全なコードを**上書き**します。

### Ruby の仕組みの活用

| 手法 | 用途 |
|------|------|
| `Module#prepend` | コントローラのアクションメソッドを上書き |
| `prepend_view_path` | ビューテンプレートを脆弱版に差し替え |
| `skip_forgery_protection` | クラスメソッド呼び出しで CSRF 無効化 |
| `Singleton` Registry | チャレンジの登録・有効化を一元管理 |
| `to_prepare` callback | dev 環境のクラスリロード時にも再注入 |

### 用意されているチャレンジ

| slug | 名前 | カテゴリ | 難易度 | CWE |
|------|------|---------|--------|-----|
| `xss_raw` | Stored XSS via html_safe | XSS | Easy | CWE-79 |
| `sql_injection` | SQL Injection via search | Injection | Medium | CWE-89 |
| `csrf_skip` | CSRF protection disabled | CSRF | Easy | CWE-352 |

### 使い方の例

```bash
# XSS だけ有効にして起動
VULN_CHALLENGES=xss_raw bin/rails server -b 127.0.0.1

# 複数同時に有効化
VULN_CHALLENGES=xss_raw,sql_injection bin/rails server -b 127.0.0.1

# 全部有効
VULN_CHALLENGES=xss_raw,sql_injection,csrf_skip bin/rails server -b 127.0.0.1
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
# 全テスト実行
bin/rails test test/integration/vulnerabilities/ -v

# 個別実行
bin/rails test test/integration/vulnerabilities/xss_raw_test.rb -v
bin/rails test test/integration/vulnerabilities/sql_injection_test.rb -v
bin/rails test test/integration/vulnerabilities/csrf_skip_test.rb -v
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

### テスト一覧

| チャレンジ | テスト名 | 種別 | 検証内容 |
|-----------|---------|------|----------|
| **XSS** | `SAFE: XSS payload is escaped in show page` | 🔴 RED | `<img>` が `&lt;img&gt;` にエスケープされる |
| | `VULN: XSS payload is rendered as raw HTML` | 🟢 GREEN | `html_safe` で生 HTML が出力される |
| **SQLi** | `SAFE: no search functionality, q parameter is ignored` | 🔴 RED | 検索ボックスなし、パラメータ無視 |
| | `VULN: SQL injection via search returns all records` | 🟢 GREEN | `' OR 1=1 OR '` で全件取得 |
| | `VULN: search box is present` | 🟢 GREEN | 脆弱な検索 UI が注入されている |
| **CSRF** | `SAFE: POST without CSRF token is rejected (422)` | 🔴 RED | トークンなし → 422 |
| | `SAFE: POST with valid CSRF token succeeds (302)` | 🔴 RED | トークンあり → 302（正常） |
| | `VULN: POST without CSRF token succeeds (302)` | 🟢 GREEN | トークンなしでも 302（攻撃成功） |
| | `VULN: task is actually created via CSRF attack` | 🟢 GREEN | タスクが実際に作成される |

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
│   ├── challenges/                      # 各チャレンジ実装
│   │   ├── xss_raw.rb
│   │   ├── sql_injection.rb
│   │   └── csrf_skip.rb
│   └── views/tasks/                     # 脆弱なテンプレート（注入用）
├── test/integration/vulnerabilities/     # E2E テスト
│   ├── e2e_helper.rb                    # サーバー管理 + セッション管理
│   ├── xss_raw_test.rb
│   ├── sql_injection_test.rb
│   └── csrf_skip_test.rb
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
