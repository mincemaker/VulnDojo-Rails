# frozen_string_literal: true

require "test_helper"
require_relative "e2e_helper"

class SessionFixationTest < ActiveSupport::TestCase
  include E2EHelper

  # Session Fixation 検証戦略:
  # ActiveRecordStore ではセッションIDがCookieに平文（サーバー側で管理）で格納される。
  # 攻撃者が事前にセッションIDを取得し、被害者に同じIDを使わせることで
  # ログイン後のセッションに便乗できる（CWE-384）。
  #
  # 攻撃フロー:
  # 1. 攻撃者: GET /login でセッションIDを取得 → _session_id=ATTACKER_ID
  # 2. 被害者: ATTACKER_ID を使ってログイン（XSS等でCookieを固定化されたシナリオ）
  # 3. VULN: reset_sessionなし → sessionsテーブルのsession_id=ATTACKER_IDの行にuser_idが追記される
  #    攻撃者: ATTACKER_IDのCookieで認証済みページにアクセス → 200（乗っ取り成功）
  # 4. SAFE: reset_sessionあり → 新しいセッションIDが発行され、ATTACKER_IDの行は削除
  #    攻撃者: ATTACKER_IDのCookieで認証済みページにアクセス → 302（ログインページへ）

  setup do
    @safe_server = ServerPool.acquire(vuln_challenges: "")
    @vuln_server = ServerPool.acquire(vuln_challenges: "session_fixation")
  end

  # 被害者ユーザを作成してログアウトし、認証情報（email/password）を返す
  def create_victim(server)
    suffix = "#{server.port}_#{SecureRandom.hex(4)}"
    email    = "victim_#{suffix}@example.com"
    name     = "victim_#{suffix}"
    password = TEST_USER_PASSWORD

    res   = server.get("/signup")
    cookie = latest_cookie(res)
    token  = extract_csrf_token(res.body)
    body   = URI.encode_www_form(
      "authenticity_token" => token,
      "user[name]"  => name,  "user[email]"  => email,
      "user[password]" => password, "user[password_confirmation]" => password
    )
    res    = server.post("/signup", body: body, headers: { "Cookie" => cookie })
    cookie = latest_cookie(res, cookie)

    # ログアウト
    res   = server.get("/tasks", headers: { "Cookie" => cookie })
    cookie = latest_cookie(res, cookie)
    csrf  = res.body.match(/name="csrf-token"\s+content="([^"]+)"/)&.[](1)
    server.delete("/logout", headers: { "Cookie" => cookie, "X-CSRF-Token" => csrf }) if csrf

    { email: email, password: password }
  end

  # 指定したCookieを使ってログイン（攻撃者のセッションを被害者に踏ませる）
  def login_with_cookie(server, cookie, email, password)
    res   = server.get("/login", headers: { "Cookie" => cookie })
    token = extract_csrf_token(res.body)
    body  = URI.encode_www_form(
      "authenticity_token" => token,
      "email" => email, "password" => password
    )
    server.post("/login", body: body, headers: { "Cookie" => cookie })
  end

  test "SAFE: session ID changes after login (reset_session)" do
    victim = create_victim(@safe_server)

    res = @safe_server.get("/login")
    pre_login_cookie = latest_cookie(res)

    login_with_cookie(@safe_server, pre_login_cookie, victim[:email], victim[:password])

    # ログイン後に新しいSet-Cookieが発行されIDが変わっていること
    # (ここでは pre_login_cookie を使ったログインレスポンスが302であればよい)
    res = @safe_server.get("/tasks", headers: { "Cookie" => pre_login_cookie })
    # reset_session後はpre_login_cookieは無効 → 302へリダイレクト
    assert_equal "302", res.code, "Pre-login cookie must be invalidated after reset_session"
  end

  test "SAFE: attacker cookie is invalidated after victim logs in" do
    victim = create_victim(@safe_server)

    # 攻撃者: セッションIDを取得
    res = @safe_server.get("/login")
    attacker_cookie = latest_cookie(res)

    # 被害者: 攻撃者のCookieを使ってログイン
    login_with_cookie(@safe_server, attacker_cookie, victim[:email], victim[:password])

    # 攻撃者: 同じCookieで認証済みページにアクセス → reset_sessionで無効化済み
    res = @safe_server.get("/tasks", headers: { "Cookie" => attacker_cookie })
    assert_equal "302", res.code,
      "Attacker cookie must be invalidated by reset_session — session fixation is prevented"
    assert_match(/login/, res["location"].to_s)
  end

  test "VULN: attacker can hijack victim session (session fixation)" do
    victim = create_victim(@vuln_server)

    # 攻撃者: セッションIDを取得（DBにレコード生成）
    res = @vuln_server.get("/login")
    attacker_cookie = latest_cookie(res)

    # 被害者: 攻撃者のCookieを使ってログイン（フィッシング等でCookieを固定化されたシナリオ）
    login_with_cookie(@vuln_server, attacker_cookie, victim[:email], victim[:password])

    # 攻撃者: 同じCookieで認証済みページにアクセス
    # reset_sessionがないため sessions テーブルの session_id=ATTACKER_ID の行に
    # user_id が追記され、攻撃者のCookieが認証済みセッションとして機能する
    res = @vuln_server.get("/tasks", headers: { "Cookie" => attacker_cookie })
    assert_equal "200", res.code,
      "Attacker must be able to use the fixed session ID (session fixation vulnerability)"
  end
end
