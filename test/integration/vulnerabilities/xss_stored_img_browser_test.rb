# frozen_string_literal: true

require "test_helper"
require_relative "browser_helper"

class XssStoredImgBrowserTest < ActiveSupport::TestCase
  include BrowserHelper

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

  setup do
    @server = ServerPool.acquire(vuln_challenges: "")
    browser_setup
  end

  teardown do
    browser_teardown
  end

  test "VULN: XSS payload in description is injected into DOM as malicious img element" do
    cookie = browser_login(@server)
    result = create_image_task_with_description(@server, description: XSS_FLAG_PAYLOAD, cookie: cookie)
    assert result[:id], "Task should be created"

    @browser.goto("http://127.0.0.1:#{@server.port}/tasks/#{result[:id]}")

    injected = @browser.at_css("img[onerror]")
    refute_nil injected, "Malicious img element MUST be in DOM: description output via html_safe"
  end

  test "VULN: onerror JS executes when CSP is disabled and XSS payload is in DOM" do
    cookie = browser_login(@server)
    result = create_image_task_with_description(@server, description: XSS_FLAG_PAYLOAD, cookie: cookie)
    assert result[:id], "Task should be created"

    @browser.goto("http://127.0.0.1:#{@server.port}/tasks/#{result[:id]}")

    assert xss_executed?,
      "JS MUST execute: CSP is disabled + description rendered via html_safe"
  end
end
