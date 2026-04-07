# frozen_string_literal: true

require "test_helper"
require_relative "e2e_helper"

class IdorTest < ActiveSupport::TestCase
  include E2EHelper

  setup do
    @safe_server = ServerProcess.new(port: 4050, vuln_challenges: "")
    @vuln_server = ServerProcess.new(port: 4051, vuln_challenges: "idor")
    @safe_server.start!
    @vuln_server.start!
  end

  teardown do
    @safe_server.stop!
    @vuln_server.stop!
  end

  test "SAFE: cannot view another user's task" do
    # User A creates a task
    cookie_a = setup_session(@safe_server)
    result_a = create_task_via_form(@safe_server, title: "User A secret", cookie: cookie_a)
    assert result_a[:id], "User A task should be created"

    # User B logs in
    cookie_b = setup_session(@safe_server)

    # User B tries to access User A's task
    res = @safe_server.get("/tasks/#{result_a[:id]}", headers: { "Cookie" => cookie_b })
    # Owner-scoped find raises RecordNotFound -> 404 or redirect
    refute_equal "200", res.code, "Must NOT return 200 for another user's task"
  end

  test "VULN: can view another user's task" do
    # User A creates a task
    cookie_a = setup_session(@vuln_server)
    result_a = create_task_via_form(@vuln_server, title: "User A secret IDOR", cookie: cookie_a)
    assert result_a[:id], "User A task should be created"

    # User B logs in
    cookie_b = setup_session(@vuln_server)

    # User B accesses User A's task
    res = @vuln_server.get("/tasks/#{result_a[:id]}", headers: { "Cookie" => cookie_b })
    assert_equal "200", res.code, "Should return 200 (IDOR vulnerability)"
    assert_includes res.body, "User A secret IDOR", "Should see User A's task content"
  end
end
