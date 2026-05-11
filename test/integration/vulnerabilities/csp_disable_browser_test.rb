# frozen_string_literal: true

require "test_helper"
require_relative "browser_helper"

class CspDisableBrowserTest < ActiveSupport::TestCase
  include BrowserHelper

  setup do
    @server = ServerPool.acquire(vuln_challenges: "")
    browser_setup
  end

  teardown do
    browser_teardown
  end

  test "VULN: disabling CSP allows inline event handler to execute with XSS payload" do
    cookie = browser_login(@server)
    result = create_task_via_form(@server, title: XSS_FLAG_PAYLOAD, cookie: cookie)
    assert result[:id], "Task should be created"

    @browser.goto("http://127.0.0.1:#{@server.port}/tasks/#{result[:id]}")

    assert xss_executed?,
      "JS MUST execute: CSP is disabled, inline event handler runs freely"
  end
end
