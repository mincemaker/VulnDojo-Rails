# frozen_string_literal: true

require "test_helper"
require_relative "browser_helper"

# XSS (Stored) のブラウザレベル検証
# 既存の xss_raw_test.rb は HTTP レスポンス本文の文字列に生 HTML が含まれるかを確認する。
# このテストは「ブラウザが DOM ツリーに悪意のある要素を生成するか」を Ferrum で検証する。
#
# なお xss_raw 単体では CSP (script-src: 'self') が有効なため onerror は実行されない。
# onerror の実行を実証する完全な exploit chain は csp_disable_browser_test.rb を参照。
class XssRawBrowserTest < ActiveSupport::TestCase
  include BrowserHelper

  setup do
    @safe_server = ServerPool.acquire(vuln_challenges: "")
    @vuln_server = ServerPool.acquire(vuln_challenges: "xss_raw")
    browser_setup
  end

  teardown do
    browser_teardown
  end

  test "SAFE: XSS payload is escaped — no malicious img element in DOM" do
    cookie = browser_login(@safe_server)
    result = create_task_via_form(@safe_server, title: XSS_FLAG_PAYLOAD, cookie: cookie)
    assert result[:id], "Task should be created"

    @browser.goto("http://127.0.0.1:#{@safe_server.port}/tasks/#{result[:id]}")

    # ERB エスケープにより &lt;img&gt; としてテキスト表示され、DOM 要素としては存在しない
    injected = @browser.at_css("img[onerror]")
    assert_nil injected, "Malicious img element must NOT be in DOM: title is HTML-escaped"
  end

  test "VULN: XSS payload is injected into DOM — malicious img element exists" do
    cookie = browser_login(@vuln_server)
    result = create_task_via_form(@vuln_server, title: XSS_FLAG_PAYLOAD, cookie: cookie)
    assert result[:id], "Task should be created"

    @browser.goto("http://127.0.0.1:#{@vuln_server.port}/tasks/#{result[:id]}")

    # html_safe により <img onerror="..."> がそのまま DOM ツリーに挿入される
    injected = @browser.at_css("img[onerror]")
    refute_nil injected, "Malicious img element MUST be in DOM: title output via html_safe"
  end
end
