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
  end

  teardown do
    @safe_server.stop!
    @vuln_server.stop!
  end

  # ---- RED: 脆弱性 OFF では CSRF トークンなしの POST が拒否される ----

  test "SAFE: POST without CSRF token is rejected (422)" do
    body = URI.encode_www_form("task[title]" => "Hacked Task")
    res = @safe_server.post("/tasks", body: body)

    assert_equal "422", res.code, "POST without CSRF token must be rejected"
  end

  test "SAFE: POST with valid CSRF token succeeds (302)" do
    # フォームを取得してトークン付きで送信
    get_res = @safe_server.get("/tasks/new")
    token = extract_csrf_token(get_res.body)
    cookie = get_res["set-cookie"]&.split(";")&.first

    body = URI.encode_www_form(
      "authenticity_token" => token,
      "task[title]" => "Legit Task"
    )
    headers = {}
    headers["Cookie"] = cookie if cookie

    res = @safe_server.post("/tasks", body: body, headers: headers)
    assert_equal "302", res.code, "POST with valid CSRF token must succeed"
  end

  # ---- GREEN: 脆弱性 ON ではトークンなしの POST が通る ----

  test "VULN: POST without CSRF token succeeds (302)" do
    body = URI.encode_www_form("task[title]" => "CSRF Attack!")
    res = @vuln_server.post("/tasks", body: body)

    assert_equal "302", res.code, "POST without CSRF token must succeed (CSRF protection disabled)"
  end

  test "VULN: task is actually created via CSRF attack" do
    body = URI.encode_www_form("task[title]" => "CSRF Created Task")
    @vuln_server.post("/tasks", body: body)

    # 一覧ページで確認
    res = @vuln_server.get("/tasks")
    assert_includes res.body, "CSRF Created Task", "Task must be created via CSRF attack"
  end
end
