# frozen_string_literal: true

require "test_helper"
require_relative "browser_helper"

# CSS Injection のブラウザレベル検証
# 既存の css_injection_test.rb は HTTP レスポンス本文に style="..." が含まれるかを確認する。
# このテストは「ブラウザが CSS を実際に適用したか」を getComputedStyle() で検証する。
class CssInjectionBrowserTest < ActiveSupport::TestCase
  include BrowserHelper

  CSS_PAYLOAD = "red; background:blue"

  setup do
    @safe_server = ServerPool.acquire(vuln_challenges: "")
    @vuln_server = ServerPool.acquire(vuln_challenges: "css_injection")
    browser_setup
  end

  teardown do
    browser_teardown
  end

  test "SAFE: color CSS payload is not injected into style attribute" do
    cookie = browser_login(@safe_server)
    result = create_task_via_form(@safe_server, title: "CSS test", color: CSS_PAYLOAD, cookie: cookie)
    assert result[:id], "Task should be created"

    @browser.goto("http://127.0.0.1:#{@safe_server.port}/tasks/#{result[:id]}")

    # 安全なテンプレートには id="task-color-indicator" が存在しない
    # (不正なカラー値は match? で弾かれスパンが非表示のため)
    element_exists = @browser.evaluate("!!document.getElementById('task-color-indicator')")
    refute element_exists, "Safe template must NOT have #task-color-indicator with injected style"
  end

  test "VULN: color CSS payload is applied as computed style in browser" do
    cookie = browser_login(@vuln_server)
    result = create_task_via_form(@vuln_server, title: "CSS test", color: CSS_PAYLOAD, cookie: cookie)
    assert result[:id], "Task should be created"

    @browser.goto("http://127.0.0.1:#{@vuln_server.port}/tasks/#{result[:id]}")

    # style="border-left: 4px solid red; background:blue" が埋め込まれ、
    # ブラウザが実際に border-left-color を適用したことを確認
    border_color = @browser.evaluate(
      "getComputedStyle(document.getElementById('task-color-indicator')).borderLeftColor"
    )
    assert_equal "rgb(255, 0, 0)", border_color,
      "Border-left MUST be red: CSS payload was injected into style attribute"
  end
end
