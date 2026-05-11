# frozen_string_literal: true

require "test_helper"
require_relative "browser_helper"

class XssRawBrowserTest < ActiveSupport::TestCase
  include BrowserHelper

  setup do
    @server = ServerPool.acquire(vuln_challenges: "")
    browser_setup
  end

  teardown do
    browser_teardown
  end

  test "VULN: XSS payload is injected into DOM — malicious img element exists" do
    cookie = browser_login(@server)
    result = create_task_via_form(@server, title: XSS_FLAG_PAYLOAD, cookie: cookie)
    assert result[:id], "Task should be created"

    @browser.goto("http://127.0.0.1:#{@server.port}/tasks/#{result[:id]}")

    injected = @browser.at_css("img[onerror]")
    refute_nil injected, "Malicious img element MUST be in DOM: title output via html_safe"
  end
end
