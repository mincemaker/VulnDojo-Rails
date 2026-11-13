# frozen_string_literal: true

require "test_helper"
require_relative "e2e_helper"

class CsrfSkipTest < ActiveSupport::TestCase
  include E2EHelper

  setup do
    @safe_server = ServerPool.acquire(vuln_challenges: "")
    @vuln_server = ServerPool.acquire(vuln_challenges: "csrf_skip")

    # 両方のサーバーでログインセッションを取得
    @safe_cookie = setup_session(@safe_server)
    @vuln_cookie = setup_session(@vuln_server)
  end

  test "SAFE: signup issues a SameSite=Lax HttpOnly session cookie" do
    cookie = signup_cookie(ServerPool.acquire(vuln_challenges: "", tls: true))

    assert_match(/; samesite=lax/i, cookie)
    assert_match(/; httponly/i, cookie)
  end

  test "VULN: signup issues a SameSite=None Secure HttpOnly session cookie" do
    cookie = signup_cookie(ServerPool.acquire(vuln_challenges: "csrf_skip", tls: true))

    assert_match(/; samesite=none/i, cookie)
    assert_match(/; secure(?:;|$)/i, cookie)
    assert_match(/; httponly/i, cookie)
  end

  test "VULN: HTTP signup retains SameSite=Lax without Secure" do
    cookie = signup_cookie(@vuln_server)

    assert_match(/; samesite=lax/i, cookie)
    refute_match(/; secure(?:;|$)/i, cookie)
  end

  # SameSite=None は Cookie を送れる条件を広げるだけ。検証は TasksController に限定されている。
  test "VULN: logout keeps CSRF verification under HTTPS" do
    server = ServerPool.acquire(vuln_challenges: "csrf_skip", tls: true)
    cookie = signup_cookie(server)

    res = server.delete("/logout", headers: { "Cookie" => cookie })
    assert_equal "422", res.code, "CSRF token must still be verified outside TasksController"
    assert_equal "200", server.get("/tasks", headers: { "Cookie" => cookie }).code
  end

  # ---- RED: 脆弱性 OFF では CSRF トークンなしの POST が拒否される ----

  test "SAFE: POST without CSRF token is rejected (422)" do
    body = URI.encode_www_form("task[title]" => "Hacked Task")
    # ログイン済みセッションを使うが、CSRFトークンなし
    res = @safe_server.post("/tasks", body: body, headers: { "Cookie" => @safe_cookie })

    assert_equal "422", res.code, "POST without CSRF token must be rejected"
  end

  test "SAFE: POST with valid CSRF token succeeds (302)" do
    get_res = @safe_server.get("/tasks/new", headers: { "Cookie" => @safe_cookie })
    token = extract_csrf_token(get_res.body)
    new_cookie = latest_cookie(get_res, @safe_cookie)

    body = URI.encode_www_form(
      "authenticity_token" => token,
      "task[title]" => "Legit Task"
    )

    res = @safe_server.post("/tasks", body: body, headers: { "Cookie" => new_cookie })
    assert_equal "302", res.code, "POST with valid CSRF token must succeed"
  end

  # ---- GREEN: 脆弱性 ON ではトークンなしの POST が通る ----

  test "VULN: POST without CSRF token succeeds (302)" do
    body = URI.encode_www_form("task[title]" => "CSRF Attack!")
    # ログイン済みセッションを使うが、CSRFトークンなし
    res = @vuln_server.post("/tasks", body: body, headers: { "Cookie" => @vuln_cookie })

    assert_equal "302", res.code, "POST without CSRF token must succeed (CSRF protection disabled)"
  end

  test "VULN: task is actually created via CSRF attack" do
    body = URI.encode_www_form("task[title]" => "CSRF Created Task")
    @vuln_server.post("/tasks", body: body, headers: { "Cookie" => @vuln_cookie })

    res = @vuln_server.get("/tasks", headers: { "Cookie" => @vuln_cookie })
    assert_includes res.body, "CSRF Created Task", "Task must be created via CSRF attack"
  end

  private

  def signup_cookie(server)
    email = "csrf_#{SecureRandom.hex(6)}@example.com"
    signup = server.get("/signup")
    created = server.post("/signup", headers: { "Cookie" => latest_cookie(signup) },
      body: URI.encode_www_form(
        "authenticity_token" => extract_csrf_token(signup.body),
        "user[name]" => email,
        "user[email]" => email,
        "user[password]" => TEST_USER_PASSWORD,
        "user[password_confirmation]" => TEST_USER_PASSWORD
      ))
    assert_equal "302", created.code
    created["set-cookie"]
  end
end
