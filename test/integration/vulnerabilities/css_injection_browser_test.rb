# frozen_string_literal: true

require "test_helper"
require_relative "browser_helper"

# CSS Injection のブラウザレベル検証
# 既存の css_injection_test.rb は HTTP レスポンス本文に style="..." が含まれるかを確認する。
# このテストは「ブラウザが CSS を実際に適用したか」を getComputedStyle() で検証する。
class CssInjectionBrowserTest < ActiveSupport::TestCase
  include BrowserHelper

  CSS_PAYLOAD = "background:red; color:white"

  setup do
    @safe_server = ServerProcess.new(port: 4202, vuln_challenges: "")
    @vuln_server = ServerProcess.new(port: 4203, vuln_challenges: "css_injection")
    @safe_server.start!
    @vuln_server.start!
    browser_setup
  end

  teardown do
    browser_teardown
    @safe_server.stop!
    @vuln_server.stop!
  end

  test "SAFE: description CSS payload is not embedded as style attribute" do
    cookie = browser_login(@safe_server)
    result = create_task_via_form(@safe_server, title: "CSS test", description: CSS_PAYLOAD, cookie: cookie)
    assert result[:id], "Task should be created"

    @browser.goto("http://127.0.0.1:#{@safe_server.port}/tasks/#{result[:id]}")

    # 安全なテンプレートには id="task-description" が存在しない
    element_exists = @browser.evaluate("!!document.getElementById('task-description')")
    refute element_exists, "Safe template must NOT have #task-description with style injection"
  end

  test "VULN: description CSS payload is applied as computed style in browser" do
    cookie = browser_login(@vuln_server)
    result = create_task_via_form(@vuln_server, title: "CSS test", description: CSS_PAYLOAD, cookie: cookie)
    assert result[:id], "Task should be created"

    @browser.goto("http://127.0.0.1:#{@vuln_server.port}/tasks/#{result[:id]}")

    # style="background:red" が埋め込まれ、ブラウザが実際に背景色を適用したことを確認
    bg_color = @browser.evaluate(
      "getComputedStyle(document.getElementById('task-description')).backgroundColor"
    )
    assert_equal "rgb(255, 0, 0)", bg_color,
      "Background MUST be red: CSS payload was injected into style attribute"
  end
end
