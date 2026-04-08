# frozen_string_literal: true

require "test_helper"
require_relative "e2e_helper"

class MassAssignmentTest < ActiveSupport::TestCase
  include E2EHelper

  setup do
    @safe_server = ServerProcess.new(port: 4070, vuln_challenges: "")
    @vuln_server = ServerProcess.new(port: 4071, vuln_challenges: "mass_assignment")
    @safe_server.start!
    @vuln_server.start!
  end

  teardown do
    @safe_server.stop!
    @vuln_server.stop!
  end

  # User A がタスクを作成し、User B がタスクを作成し、
  # User A が自分のタスクの user_id を User B のタスクの user_id に変更しようとする
  def attempt_user_id_overwrite(server)
    # User A: create task
    cookie_a = setup_session(server)
    result_a = create_task_via_form(server, title: "UserA Task", cookie: cookie_a)
    cookie_a = result_a[:cookie]
    task_a_id = result_a[:id]

    # User B: create task (to get a valid user_id)
    cookie_b = setup_session(server)
    result_b = create_task_via_form(server, title: "UserB Task", cookie: cookie_b)
    cookie_b = result_b[:cookie]
    task_b_id = result_b[:id]

    # User B reads their task to find their user_id isn't directly visible,
    # but we know task_b belongs to user B. We'll try to set user_id
    # of User A's task to make it "disappear" from User A.
    # We don't know User B's user_id, but we can try sequential IDs.
    # Easier: just use user_id from task_b by trying IDs 1..10

    # User A edits their own task, injecting various user_id values
    res = server.get("/tasks/#{task_a_id}/edit", headers: { "Cookie" => cookie_a })
    cookie_a = latest_cookie(res, cookie_a)
    token = extract_csrf_token(res.body)

    # Try user_id = 1, 2, ... — one of them is User B
    # We'll try a range and see if the task disappears from User A
    (1..20).each do |uid|
      body = URI.encode_www_form(
        "authenticity_token" => token,
        "_method"            => "patch",
        "task[title]"        => "UserA Task",
        "task[user_id]"      => uid.to_s
      )
      server.post("/tasks/#{task_a_id}", body: body, headers: { "Cookie" => cookie_a })

      # Re-fetch edit page for fresh CSRF token
      res = server.get("/tasks/#{task_a_id}/edit", headers: { "Cookie" => cookie_a })
      if res.code != "200"
        # Task is no longer accessible = user_id was changed
        return { stolen: true, cookie_a: cookie_a, task_id: task_a_id }
      end
      cookie_a = latest_cookie(res, cookie_a)
      token = extract_csrf_token(res.body)
    end

    { stolen: false, cookie_a: cookie_a, task_id: task_a_id }
  end

  test "SAFE: user_id parameter is ignored by strong parameters" do
    result = attempt_user_id_overwrite(@safe_server)
    refute result[:stolen], "user_id should NOT be overwritable with strong parameters"
  end

  test "VULN: user_id can be overwritten via permit!" do
    result = attempt_user_id_overwrite(@vuln_server)
    assert result[:stolen], "user_id should be overwritable with permit! (mass assignment vulnerability)"
  end

  # updated_at を任意の値に上書きできるかを検証する
  # show ページに updated_at が表示されるようになったため、視覚的にも確認可能
  def attempt_updated_at_overwrite(server)
    cookie = setup_session(server)
    result = create_task_via_form(server, title: "Timestamp Task", cookie: cookie)
    cookie = result[:cookie]
    task_id = result[:id]

    # Get edit page for CSRF token
    res = server.get("/tasks/#{task_id}/edit", headers: { "Cookie" => cookie })
    cookie = latest_cookie(res, cookie)
    token = extract_csrf_token(res.body)

    injected_time = "2000-01-01 00:00:00"
    body = URI.encode_www_form(
      "authenticity_token" => token,
      "_method"            => "patch",
      "task[title]"        => "Timestamp Task",
      "task[updated_at]"   => injected_time
    )
    server.post("/tasks/#{task_id}", body: body, headers: { "Cookie" => cookie })

    # show ページで updated_at の表示値を確認
    res = server.get("/tasks/#{task_id}", headers: { "Cookie" => cookie })
    res.body.include?(injected_time)
  end

  test "SAFE: updated_at parameter is ignored by strong parameters" do
    overwritten = attempt_updated_at_overwrite(@safe_server)
    refute overwritten, "updated_at should NOT be overwritable with strong parameters"
  end

  test "VULN: updated_at can be overwritten via permit!" do
    overwritten = attempt_updated_at_overwrite(@vuln_server)
    assert overwritten, "updated_at should be overwritable with permit! (mass assignment vulnerability)"
  end
end
