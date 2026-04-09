# frozen_string_literal: true

require "test_helper"
require_relative "e2e_helper"

class SqlInjectionActiveRecordTest < ActiveSupport::TestCase
  include E2EHelper

  setup do
    @safe_server = ServerPool.acquire(vuln_challenges: "")
    @vuln_server = ServerPool.acquire(vuln_challenges: "sql_injection_active_record")

    # User A と User B をそれぞれ作成し、未完了タスクを1件ずつ登録する
    @safe_cookie_a = setup_session(@safe_server)
    create_task_via_form(@safe_server, title: "UserA Todo Task", cookie: @safe_cookie_a)
    @safe_cookie_b = setup_session(@safe_server)
    create_task_via_form(@safe_server, title: "UserB Todo Task", cookie: @safe_cookie_b)

    @vuln_cookie_a = setup_session(@vuln_server)
    create_task_via_form(@vuln_server, title: "UserA Todo Task", cookie: @vuln_cookie_a)
    @vuln_cookie_b = setup_session(@vuln_server)
    create_task_via_form(@vuln_server, title: "UserB Todo Task", cookie: @vuln_cookie_b)
  end

  # from() への直接注入: CTE スコープをバイパスして tasks テーブル全体を参照させる
  SQLI_PAYLOAD = "tasks"

  test "SAFE: view filter tabs exist and unknown view_type cannot bypass user scope" do
    res = @safe_server.get("/tasks?view_type=#{SQLI_PAYLOAD}",
                           headers: { "Cookie" => @safe_cookie_a })
    body = res.body

    assert_includes body, "todo_tasks", "Filter tab links must be present"
    assert_includes body, "UserA Todo Task"
    refute_includes body, "UserB Todo Task", "Whitelisted view_type must never leak another user's tasks"
  end

  test "VULN: todo_tasks view shows only current user's incomplete tasks" do
    res = @vuln_server.get("/tasks?view_type=todo_tasks",
                           headers: { "Cookie" => @vuln_cookie_a })
    body = res.body

    assert_includes body, "UserA Todo Task"
    refute_includes body, "UserB Todo Task",
                    "CTE scope must restrict results to current_user"
  end

  test "VULN: done_tasks view shows only current user's completed tasks" do
    # User A の完了タスクを作成
    res1 = @vuln_server.get("/tasks/new", headers: { "Cookie" => @vuln_cookie_a })
    token = extract_csrf_token(res1.body)
    body_params = URI.encode_www_form(
      "authenticity_token" => token,
      "task[title]" => "UserA Done Task",
      "task[completed]" => "1"
    )
    @vuln_server.post("/tasks", body: body_params, headers: { "Cookie" => @vuln_cookie_a })

    res = @vuln_server.get("/tasks?view_type=done_tasks",
                           headers: { "Cookie" => @vuln_cookie_a })
    body = res.body

    assert_includes body, "UserA Done Task"
    refute_includes body, "UserB Todo Task",
                    "done_tasks CTE must be scoped to current_user"
  end

  test "VULN: from() injection bypasses CTE user scope and leaks all tasks" do
    # view_type=tasks で from() に直接テーブル名を注入
    # → WITH 句のユーザースコープを完全にバイパスして全タスクが見える
    res = @vuln_server.get("/tasks?view_type=#{URI.encode_www_form_component(SQLI_PAYLOAD)}",
                           headers: { "Cookie" => @vuln_cookie_a })
    body = res.body

    assert_includes body, "UserA Todo Task", "Own task must appear"
    assert_includes body, "UserB Todo Task",
                    "Injection must leak UserB's task that UserA should never see"
  end
end
