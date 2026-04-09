# frozen_string_literal: true

require "test_helper"
require_relative "browser_helper"

# CSP 無効化のブラウザレベル検証
# 既存の csp_disable_test.rb は CSP ヘッダの有無を HTTP レベルで確認する。
# このテストは「CSP が onerror インラインハンドラの実行をブロックするか」を検証する。
#
# テスト構成:
#   safe_server: xss_raw のみ有効 (CSP あり) → html_safe で XSS payload が DOM に挿入されるが、
#                CSP の script-src: 'self' がインラインイベントハンドラをブロックする
#   vuln_server: xss_raw + csp_disable → CSP なしで onerror が実行される
#
# これにより CSP が提供する「多層防御」としての価値を実証する。
class CspDisableBrowserTest < ActiveSupport::TestCase
  include BrowserHelper

  setup do
    # safe_server: xss_raw のみ (CSP 有効) — html_safe でペイロードが DOM に挿入されるが CSP がブロック
    # vuln_server: xss_raw + csp_disable — CSP なしで onerror が実行される完全な exploit chain
    @safe_server = ServerPool.acquire(vuln_challenges: "xss_raw")
    @vuln_server = ServerPool.acquire(vuln_challenges: "xss_raw,csp_disable")
    browser_setup
  end

  teardown do
    browser_teardown
  end

  test "SAFE: CSP blocks inline event handler even when html_safe is active" do
    cookie = browser_login(@safe_server)
    result = create_task_via_form(@safe_server, title: XSS_FLAG_PAYLOAD, cookie: cookie)
    assert result[:id], "Task should be created"

    @browser.goto("http://127.0.0.1:#{@safe_server.port}/tasks/#{result[:id]}")

    # html_safe で <img onerror> がそのまま DOM に挿入されるが、
    # CSP (script-src: 'self') がインラインイベントハンドラをブロックする
    refute xss_executed?,
      "JS must NOT execute: CSP script-src 'self' blocks inline event handlers"
  end

  test "VULN: disabling CSP allows inline event handler to execute" do
    cookie = browser_login(@vuln_server)
    result = create_task_via_form(@vuln_server, title: XSS_FLAG_PAYLOAD, cookie: cookie)
    assert result[:id], "Task should be created"

    @browser.goto("http://127.0.0.1:#{@vuln_server.port}/tasks/#{result[:id]}")

    # CSP が無効 + html_safe → onerror ハンドラが実行される
    assert xss_executed?,
      "JS MUST execute: CSP is disabled, inline event handler runs freely"
  end
end
