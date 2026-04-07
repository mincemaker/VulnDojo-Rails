# frozen_string_literal: true

require "test_helper"
require_relative "e2e_helper"

class SqlInjectionTest < ActiveSupport::TestCase
  include E2EHelper

  # SQLite では LIKE '%...%' の中に注入するので
  # title LIKE '%' OR 1=1 OR '%' = '%' になるようにする
  SQLI_PAYLOAD = "' OR 1=1 OR '"

  setup do
    @safe_server = ServerProcess.new(port: 4020, vuln_challenges: "")
    @vuln_server = ServerProcess.new(port: 4021, vuln_challenges: "sql_injection")
    @safe_server.start!
    @vuln_server.start!

    # 両方にテストデータを作成
    create_task_via_form(@safe_server, title: "Secret Task A")
    create_task_via_form(@safe_server, title: "Public Task B")
    create_task_via_form(@vuln_server, title: "Secret Task A")
    create_task_via_form(@vuln_server, title: "Public Task B")
  end

  teardown do
    @safe_server.stop!
    @vuln_server.stop!
  end

  # ---- RED: 脆弱性 OFF では検索機能がないので SQLi がそもそも不可能 ----

  test "SAFE: no search functionality, q parameter is ignored" do
    res = @safe_server.get("/tasks?q=#{URI.encode_www_form_component(SQLI_PAYLOAD)}")
    body = res.body

    # 検索ボックスが存在しない
    refute_includes body, 'name="q"', "Search box must NOT exist in safe mode"

    # タスクが普通に表示される（全件）
    assert_includes body, "Secret Task A"
    assert_includes body, "Public Task B"
  end

  # ---- GREEN: 脆弱性 ON では SQLi が通る ----

  test "VULN: SQL injection via search returns all records" do
    # まず通常検索で一部だけヒットすることを確認
    res_normal = @vuln_server.get("/tasks?q=#{URI.encode_www_form_component('Secret')}")
    assert_includes res_normal.body, "Secret Task A"
    refute_includes res_normal.body, "Public Task B"

    # SQLi で全件取得
    res_sqli = @vuln_server.get("/tasks?q=#{URI.encode_www_form_component(SQLI_PAYLOAD)}")
    body = res_sqli.body

    assert_includes body, "Secret Task A", "SQLi must return all records"
    assert_includes body, "Public Task B", "SQLi must return all records"
  end

  test "VULN: search box is present" do
    res = @vuln_server.get("/tasks")
    assert_includes res.body, 'name="q"', "Search box must exist in vulnerable mode"
  end
end
