# frozen_string_literal: true

require "test_helper"
require_relative "browser_helper"

# Stored XSS via image caption (html_safe description) のブラウザレベル検証
#
# 既存の xss_stored_img_test.rb は HTTP レスポンス本文に生 HTML タグが含まれるかを確認する。
# このテストは「ブラウザが DOM ツリーに悪意ある要素を生成するか」を Ferrum で検証する。
#
# xss_stored_img 単体では CSP (script-src: 'self') が有効なため onerror は実行されない。
# onerror の実行 (完全な exploit chain) は xss_stored_img + csp_disable の組み合わせで検証する。
class XssStoredImgBrowserTest < ActiveSupport::TestCase
  include BrowserHelper

  # image/png を添付し description に XSS ペイロードを入れたタスクを作成する
  # 戻り値: { id:, cookie: }
  def create_image_task_with_description(server, description:, cookie: nil)
    cookie ||= setup_session(server)

    res = server.get("/tasks/new", headers: { "Cookie" => cookie })
    cookie = latest_cookie(res, cookie)
    token = extract_csrf_token(res.body)

    boundary = "----E2EBoundary#{SecureRandom.hex(8)}"
    body = String.new(encoding: "BINARY")
    [
      ["authenticity_token", token],
      ["task[title]",        "Stored XSS browser test"],
      ["task[description]",  description],
    ].each do |name, value|
      body << "--#{boundary}\r\n"
      body << "Content-Disposition: form-data; name=\"#{name}\"\r\n\r\n"
      body << "#{value}\r\n"
    end
    body << "--#{boundary}\r\n"
    body << "Content-Disposition: form-data; name=\"task[attachment]\"; filename=\"photo.png\"\r\n"
    body << "Content-Type: image/png\r\n\r\n"
    body << "\x89PNG\r\n\x1a\n\r\n"
    body << "--#{boundary}--\r\n"

    uri = URI("http://127.0.0.1:#{server.port}/tasks")
    req = Net::HTTP::Post.new(uri)
    req["Cookie"] = cookie
    req["Content-Type"] = "multipart/form-data; boundary=#{boundary}"
    req.body = body

    res = Net::HTTP.start(uri.host, uri.port) { |http| http.request(req) }
    cookie = latest_cookie(res, cookie)

    task_id = nil
    if res["location"]
      m = res["location"].match(%r{/tasks/(\d+)})
      task_id = m[1].to_i if m
    end
    { id: task_id, cookie: cookie }
  end

  # ── DOM 挿入の検証 (CSP あり) ──

  setup do
    @safe_server = ServerPool.acquire(vuln_challenges: "")
    @vuln_server = ServerPool.acquire(vuln_challenges: "xss_stored_img")
    browser_setup
  end

  teardown do
    browser_teardown
  end

  test "SAFE: XSS payload in description is escaped — no malicious img element in DOM" do
    cookie = browser_login(@safe_server)
    result = create_image_task_with_description(@safe_server, description: XSS_FLAG_PAYLOAD, cookie: cookie)
    assert result[:id], "Task should be created"

    @browser.goto("http://127.0.0.1:#{@safe_server.port}/tasks/#{result[:id]}")

    injected = @browser.at_css("img[onerror]")
    assert_nil injected, "Malicious img element must NOT be in DOM: description is HTML-escaped"
  end

  test "VULN: XSS payload in description is injected into DOM as malicious img element" do
    cookie = browser_login(@vuln_server)
    result = create_image_task_with_description(@vuln_server, description: XSS_FLAG_PAYLOAD, cookie: cookie)
    assert result[:id], "Task should be created"

    @browser.goto("http://127.0.0.1:#{@vuln_server.port}/tasks/#{result[:id]}")

    # html_safe により <img onerror="..."> がそのまま DOM ツリーに挿入される
    injected = @browser.at_css("img[onerror]")
    refute_nil injected, "Malicious img element MUST be in DOM: description output via html_safe"
  end

  # ── JS 実行の検証 (xss_stored_img + csp_disable の完全な exploit chain) ──

  test "SAFE: CSP blocks onerror execution even when XSS payload is in DOM" do
    # xss_stored_img のみ (CSP 有効) — payload は DOM に挿入されるが JS はブロックされる
    cookie = browser_login(@vuln_server)
    result = create_image_task_with_description(@vuln_server, description: XSS_FLAG_PAYLOAD, cookie: cookie)
    assert result[:id], "Task should be created"

    @browser.goto("http://127.0.0.1:#{@vuln_server.port}/tasks/#{result[:id]}")

    refute xss_executed?,
      "JS must NOT execute: CSP script-src 'self' blocks inline event handlers"
  end

  test "VULN: disabling CSP allows onerror to execute when XSS payload is in DOM" do
    # xss_stored_img + csp_disable — 完全な exploit chain
    vuln_full = ServerPool.acquire(vuln_challenges: "xss_stored_img,csp_disable")
    cookie = browser_login(vuln_full)
    result = create_image_task_with_description(vuln_full, description: XSS_FLAG_PAYLOAD, cookie: cookie)
    assert result[:id], "Task should be created"

    @browser.goto("http://127.0.0.1:#{vuln_full.port}/tasks/#{result[:id]}")

    assert xss_executed?,
      "JS MUST execute: CSP is disabled + description rendered via html_safe"
  end
end
