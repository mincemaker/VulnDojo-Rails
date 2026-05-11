# frozen_string_literal: true

require "test_helper"
require_relative "browser_helper"

class CssInjectionBrowserTest < ActiveSupport::TestCase
  include BrowserHelper

  CSS_PAYLOAD = "red; background:blue"

  setup do
    @server = ServerPool.acquire(vuln_challenges: "")
    browser_setup
  end

  teardown do
    browser_teardown
  end

  test "VULN: color CSS payload is applied as computed style in browser" do
    cookie = browser_login(@server)
    result = create_task_via_form(@server, title: "CSS test", color: CSS_PAYLOAD, cookie: cookie)
    assert result[:id], "Task should be created"

    @browser.goto("http://127.0.0.1:#{@server.port}/tasks/#{result[:id]}")

    border_color = @browser.evaluate(
      "getComputedStyle(document.getElementById('task-color-indicator')).borderLeftColor"
    )
    assert_equal "rgb(255, 0, 0)", border_color,
      "Border-left MUST be red: CSS payload was injected into style attribute"
  end
end
