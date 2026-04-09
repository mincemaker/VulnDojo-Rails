# frozen_string_literal: true

require "test_helper"
require_relative "e2e_helper"

# E2E: ORDER injection の動作確認
class SqlInjectionOrderTest < ActiveSupport::TestCase
  include E2EHelper

  # sort=title で並び替えると Apple → Cherry の順になる (ASC)
  # 注入なしの created_at DESC では Cherry → Apple
  ORDER_INJECTION_PAYLOAD = "title"
  BLIND_INJECTION_PAYLOAD = "(CASE WHEN 1=1 THEN title ELSE created_at END)"

  setup do
    @safe_server = ServerProcess.new(port: 4024, vuln_challenges: "")
    @vuln_server = ServerProcess.new(port: 4025, vuln_challenges: "sql_injection_order")
    @safe_server.start!
    @vuln_server.start!

    # "Apple" を先に、"Cherry" を後に作成する。
    # created_at DESC (デフォルト) では Cherry → Apple の順になる。
    # sort=title (注入成功) では Apple → Cherry の順になる。
    @safe_cookie  = setup_session(@safe_server)
    create_task_via_form(@safe_server, title: "Apple Sorted Task", cookie: @safe_cookie)
    create_task_via_form(@safe_server, title: "Cherry Sorted Task", cookie: @safe_cookie)

    @vuln_cookie  = setup_session(@vuln_server)
    create_task_via_form(@vuln_server, title: "Apple Sorted Task", cookie: @vuln_cookie)
    create_task_via_form(@vuln_server, title: "Cherry Sorted Task", cookie: @vuln_cookie)
  end

  teardown do
    @safe_server.stop!
    @vuln_server.stop!
  end

  # --- SAFE モード ---

  test "SAFE: tasks are listed in created_at DESC order by default" do
    res = @safe_server.get("/tasks", headers: { "Cookie" => @safe_cookie })
    body = res.body

    assert_includes body, "Apple Sorted Task"
    assert_includes body, "Cherry Sorted Task"
    # Cherry を後に作ったので created_at DESC では Cherry が先頭
    assert body.index("Cherry Sorted Task") < body.index("Apple Sorted Task"),
           "Safe mode must show Cherry (created last) before Apple (created first)"
  end

  test "SAFE: sort param is ignored and order remains created_at DESC" do
    res = @safe_server.get("/tasks?sort=#{URI.encode_www_form_component(ORDER_INJECTION_PAYLOAD)}",
                           headers: { "Cookie" => @safe_cookie })
    body = res.body

    # sort param が無視されるため Cherry が先頭のまま
    assert body.index("Cherry Sorted Task") < body.index("Apple Sorted Task"),
           "Safe mode must ignore sort param and keep created_at DESC order"
  end

  # --- VULN モード ---

  test "VULN: default order is created_at DESC without sort param" do
    res = @vuln_server.get("/tasks", headers: { "Cookie" => @vuln_cookie })
    body = res.body

    assert body.index("Cherry Sorted Task") < body.index("Apple Sorted Task"),
           "Vulnerable mode without sort param must still show Cherry before Apple"
  end

  test "VULN: sort=title injection changes order to alphabetical ASC" do
    res = @vuln_server.get("/tasks?sort=#{URI.encode_www_form_component(ORDER_INJECTION_PAYLOAD)}",
                           headers: { "Cookie" => @vuln_cookie })
    body = res.body

    # ORDER BY title が注入されると Apple が先頭になる
    assert body.index("Apple Sorted Task") < body.index("Cherry Sorted Task"),
           "ORDER injection via sort=title must show Apple (A) before Cherry (C)"
  end

  test "VULN: CASE WHEN expression is accepted as SQL injection payload" do
    payload = URI.encode_www_form_component(BLIND_INJECTION_PAYLOAD)
    res = @vuln_server.get("/tasks?sort=#{payload}", headers: { "Cookie" => @vuln_cookie })

    # 1=1 が常に true なので title で並び替えられ Apple が先頭になる
    body = res.body
    assert_equal "200", res.code, "Blind injection payload must not cause a 500 error"
    assert body.index("Apple Sorted Task") < body.index("Cherry Sorted Task"),
           "CASE WHEN 1=1 THEN title ... must resolve to title order (Apple first)"
  end
end

# 単体: sql_injection と sql_injection_order の conflict 検出
class SqlInjectionOrderConflictTest < ActiveSupport::TestCase
  setup do
    @registry = Vulnerabilities::Registry.instance
    @original_active     = @registry.instance_variable_get(:@active).dup
    @original_conflict_log = @registry.instance_variable_get(:@conflict_log).dup
    @registry.instance_variable_set(:@active, Set.new)
    @registry.instance_variable_set(:@conflict_log, [])

    @registry.enable("sql_injection")
    @registry.enable("sql_injection_order")
  end

  teardown do
    @registry.instance_variable_set(:@active, @original_active)
    @registry.instance_variable_set(:@conflict_log, @original_conflict_log)
  end

  test "conflict is detected on TasksController#apply_task_search slot" do
    @registry.send(:resolve_conflicts!)

    assert_equal 1, @registry.conflict_log.size
    entry = @registry.conflict_log.first
    assert_equal "TasksController#apply_task_search", entry[:slot]
    assert_includes %w[sql_injection sql_injection_order], entry[:winner]
    assert_equal 1, entry[:losers].size
  end

  test "only one challenge remains active after conflict resolution" do
    @registry.send(:resolve_conflicts!)

    assert_equal 1, @registry.active_slugs.size
    assert(
      @registry.active_slugs.include?("sql_injection") ||
      @registry.active_slugs.include?("sql_injection_order"),
      "Either sql_injection or sql_injection_order must survive"
    )
  end
end
