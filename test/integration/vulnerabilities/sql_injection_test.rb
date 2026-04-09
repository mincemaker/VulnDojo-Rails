# frozen_string_literal: true

require "test_helper"
require_relative "e2e_helper"

class SqlInjectionTest < ActiveSupport::TestCase
  include E2EHelper

  SQLI_PAYLOAD = "' OR 1=1 OR '"

  setup do
    @safe_server = ServerProcess.new(port: 4020, vuln_challenges: "")
    @vuln_server = ServerProcess.new(port: 4021, vuln_challenges: "sql_injection")
    @safe_server.start!
    @vuln_server.start!

    # User A と User B をそれぞれ別セッションで作成
    # User A のタスクは User B からは（正常なら）見えないはずのデータ
    @safe_cookie_a  = setup_session(@safe_server)
    create_task_via_form(@safe_server, title: "UserA Private Task", cookie: @safe_cookie_a)
    @safe_cookie_b  = setup_session(@safe_server)
    create_task_via_form(@safe_server, title: "UserB Private Task", cookie: @safe_cookie_b)

    @vuln_cookie_a  = setup_session(@vuln_server)
    create_task_via_form(@vuln_server, title: "UserA Private Task", cookie: @vuln_cookie_a)
    @vuln_cookie_b  = setup_session(@vuln_server)
    create_task_via_form(@vuln_server, title: "UserB Private Task", cookie: @vuln_cookie_b)
  end

  teardown do
    @safe_server.stop!
    @vuln_server.stop!
  end

  test "SAFE: normal search returns matching results scoped to current user" do
    res = @safe_server.get("/tasks?q=#{URI.encode_www_form_component('UserA')}",
                           headers: { "Cookie" => @safe_cookie_a })
    body = res.body

    assert_includes body, 'name="q"', "Search box must exist in safe mode"
    assert_includes body, "UserA Private Task", "Matching task must appear in search results"
    refute_includes body, "UserB Private Task", "Other user's tasks must not appear"
  end

  test "SAFE: SQLi payload does not leak other users tasks" do
    res = @safe_server.get("/tasks?q=#{URI.encode_www_form_component(SQLI_PAYLOAD)}",
                           headers: { "Cookie" => @safe_cookie_a })
    body = res.body

    refute_includes body, "UserA Private Task", "SQLi payload as literal string should match no tasks"
    refute_includes body, "UserB Private Task", "SQLi payload must NOT leak other user's tasks"
  end

  test "VULN: search functionality is available on index page" do
    res = @vuln_server.get("/tasks", headers: { "Cookie" => @vuln_cookie_a })
    assert_includes res.body, 'name="q"', "Search box must exist in vulnerable mode"
  end

  test "VULN: empty search query properly scopes tasks to current user" do
    res = @vuln_server.get("/tasks", headers: { "Cookie" => @vuln_cookie_a })
    body = res.body
    assert_includes body, "UserA Private Task"
    refute_includes body, "UserB Private Task",
                    "Implementation error: index without q must be scoped to current_user"
  end

  test "VULN: normal search does not leak other users tasks even if queried" do
    # User A が他人のタスク（UserB）を検索してもヒットしないことを確認
    res = @vuln_server.get("/tasks?q=#{URI.encode_www_form_component('UserB')}",
                           headers: { "Cookie" => @vuln_cookie_a })
    refute_includes res.body, "UserB Private Task",
                    "Normal search must NOT leak another user's tasks even when specifically searched"
  end

  test "VULN: SQL injection payload bypasses user scope and leaks data" do
    res = @vuln_server.get("/tasks?q=#{URI.encode_www_form_component(SQLI_PAYLOAD)}",
                           headers: { "Cookie" => @vuln_cookie_a })
    body = res.body

    assert_includes body, "UserA Private Task", "Own task must appear"
    assert_includes body, "UserB Private Task",
                    "SQLi must leak UserB's task that UserA should never see"
  end
end
