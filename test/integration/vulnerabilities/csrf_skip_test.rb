# frozen_string_literal: true

require "test_helper"
require_relative "e2e_helper"

class CsrfSkipTest < ActiveSupport::TestCase
  include E2EHelper

  setup do
    @safe_server = ServerProcess.new(port: 4030, vuln_challenges: "")
    @vuln_server = ServerProcess.new(port: 4031, vuln_challenges: "csrf_skip")
    @safe_server.start!
    @vuln_server.start!

    # 両方のサーバーでログインセッションを取得
    @safe_cookie = setup_session(@safe_server)
    @vuln_cookie = setup_session(@vuln_server)
  end

  teardown do
    @safe_server.stop!
    @vuln_server.stop!
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
end
