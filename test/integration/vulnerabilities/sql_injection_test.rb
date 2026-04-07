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

    # 両方にテストデータを作成
    @safe_cookie = create_task_via_form(@safe_server, title: "Secret Task A")[:cookie]
    create_task_via_form(@safe_server, title: "Public Task B", cookie: @safe_cookie)
    @vuln_cookie = create_task_via_form(@vuln_server, title: "Secret Task A")[:cookie]
    create_task_via_form(@vuln_server, title: "Public Task B", cookie: @vuln_cookie)
  end

  teardown do
    @safe_server.stop!
    @vuln_server.stop!
  end

  test "SAFE: no search functionality, q parameter is ignored" do
    res = @safe_server.get("/tasks?q=#{URI.encode_www_form_component(SQLI_PAYLOAD)}",
                           headers: { "Cookie" => @safe_cookie })
    body = res.body

    refute_includes body, 'name="q"', "Search box must NOT exist in safe mode"
    assert_includes body, "Secret Task A"
    assert_includes body, "Public Task B"
  end

  test "VULN: SQL injection via search returns all records" do
    res_normal = @vuln_server.get("/tasks?q=#{URI.encode_www_form_component('Secret')}",
                                  headers: { "Cookie" => @vuln_cookie })
    assert_includes res_normal.body, "Secret Task A"
    refute_includes res_normal.body, "Public Task B"

    res_sqli = @vuln_server.get("/tasks?q=#{URI.encode_www_form_component(SQLI_PAYLOAD)}",
                                headers: { "Cookie" => @vuln_cookie })
    body = res_sqli.body

    assert_includes body, "Secret Task A", "SQLi must return all records"
    assert_includes body, "Public Task B", "SQLi must return all records"
  end

  test "VULN: search box is present" do
    res = @vuln_server.get("/tasks", headers: { "Cookie" => @vuln_cookie })
    assert_includes res.body, 'name="q"', "Search box must exist in vulnerable mode"
  end
end
