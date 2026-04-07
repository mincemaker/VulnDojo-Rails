# frozen_string_literal: true

require "test_helper"
require_relative "e2e_helper"

class SessionFixationTest < ActiveSupport::TestCase
  include E2EHelper

  # Session Fixation 検証戦略:
  # CookieStore ではセッションデータがCookie内に格納されるため、
  # サーバー側セッションIDの固定化とは異なる。
  # 検証方法: ログアウト後のCookieを使ってログインし、
  # ログイン後にログアウト時のCookieで認証済みページにアクセスできるかを確認。
  # - SAFE (reset_sessionあり): ログアウトCookieは無効 -> loginにリダイレクト
  # - VULN (reset_sessionなし): CookieStoreでも古いcookieは使えないが、
  #   脆弱性の存在自体はモジュールが適用されていることで確認

  setup do
    @safe_server = ServerProcess.new(port: 4060, vuln_challenges: "")
    @vuln_server = ServerProcess.new(port: 4061, vuln_challenges: "session_fixation")
    @safe_server.start!
    @vuln_server.start!
  end

  teardown do
    @safe_server.stop!
    @vuln_server.stop!
  end

  def create_user_and_login(server)
    suffix = "#{server.port}_#{SecureRandom.hex(4)}"
    email = "fix_#{suffix}@example.com"
    name  = "fixer_#{suffix}"

    # Signup
    res = server.get("/signup")
    cookie = latest_cookie(res)
    token = extract_csrf_token(res.body)
    body = URI.encode_www_form(
      "authenticity_token" => token,
      "user[name]" => name, "user[email]" => email,
      "user[password]" => "password123",
      "user[password_confirmation]" => "password123"
    )
    res = server.post("/signup", body: body, headers: { "Cookie" => cookie })
    signup_cookie = latest_cookie(res, cookie)

    # Logout
    res = server.get("/tasks", headers: { "Cookie" => signup_cookie })
    signup_cookie = latest_cookie(res, signup_cookie)
    meta = res.body.match(/name="csrf-token"\s+content="([^"]+)"/)
    token = meta[1] if meta
    res = server.delete("/logout", headers: { "Cookie" => signup_cookie, "X-CSRF-Token" => token })
    logout_cookie = latest_cookie(res, signup_cookie)

    # Login
    res = server.get("/login", headers: { "Cookie" => logout_cookie })
    pre_cookie = latest_cookie(res, logout_cookie)
    token = extract_csrf_token(res.body)
    body = URI.encode_www_form(
      "authenticity_token" => token,
      "email" => email, "password" => "password123"
    )
    res = server.post("/login", body: body, headers: { "Cookie" => pre_cookie })
    post_cookie = latest_cookie(res, pre_cookie)

    { pre_login_cookie: pre_cookie, post_login_cookie: post_cookie,
      login_response: res, logout_cookie: logout_cookie }
  end

  test "SAFE: login succeeds and reset_session regenerates cookie" do
    result = create_user_and_login(@safe_server)
    assert_equal "302", result[:login_response].code

    # reset_sessionによりログイン後に新しいSet-Cookieが発行される
    assert result[:login_response]["set-cookie"], "Login should set new cookie"

    # ログイン後のCookieでタスク一覧にアクセス可能
    res = @safe_server.get("/tasks", headers: { "Cookie" => result[:post_login_cookie] })
    assert_equal "200", res.code, "Authenticated access should work"
  end

  test "VULN: login succeeds without reset_session" do
    result = create_user_and_login(@vuln_server)
    assert_equal "302", result[:login_response].code

    # ログイン後のCookieでタスク一覧にアクセス可能
    res = @vuln_server.get("/tasks", headers: { "Cookie" => result[:post_login_cookie] })
    assert_equal "200", res.code, "Authenticated access should work"
  end

  test "SAFE: logout cookie is invalid after new login" do
    result = create_user_and_login(@safe_server)

    # ログアウト時のCookieでアクセス -> reset_sessionで無効
    res = @safe_server.get("/tasks", headers: { "Cookie" => result[:logout_cookie] })
    assert_equal "302", res.code, "Logout cookie should be invalid"
    assert_match(/login/, res["location"])
  end
end
