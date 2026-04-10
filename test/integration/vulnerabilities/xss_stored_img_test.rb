# frozen_string_literal: true

require "test_helper"
require_relative "e2e_helper"

class XssStoredImgTest < ActiveSupport::TestCase
  include E2EHelper

  XSS_PAYLOAD = '<img src=x onerror=alert(1)>'

  setup do
    @safe_server = ServerPool.acquire(vuln_challenges: "")
    @vuln_server = ServerPool.acquire(vuln_challenges: "xss_stored_img")
  end

  # description に XSS ペイロードを含み、PNG 画像を添付してタスクを作成
  # 戻り値: { id:, cookie: }
  def create_image_task_with_description(server, description:)
    cookie = setup_session(server)

    res = server.get("/tasks/new", headers: { "Cookie" => cookie })
    cookie = latest_cookie(res, cookie)
    token = extract_csrf_token(res.body)

    boundary = "----E2EBoundary#{SecureRandom.hex(8)}"
    body = String.new(encoding: "BINARY")
    [
      ["authenticity_token", token],
      ["task[title]",        "Stored XSS image test"],
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

  test "SAFE: XSS payload in description is escaped when image is attached" do
    result = create_image_task_with_description(@safe_server, description: XSS_PAYLOAD)
    assert result[:id], "Task should be created"

    res = @safe_server.get("/tasks/#{result[:id]}", headers: { "Cookie" => result[:cookie] })
    body = res.body

    refute_includes body, '<img src=x onerror', "Raw XSS tag must NOT appear in the page"
  end

  test "VULN: XSS payload in description is rendered as raw HTML in image caption" do
    result = create_image_task_with_description(@vuln_server, description: XSS_PAYLOAD)
    assert result[:id], "Task should be created"

    res = @vuln_server.get("/tasks/#{result[:id]}", headers: { "Cookie" => result[:cookie] })
    body = res.body

    assert_includes body, '<img src=x onerror', "Raw XSS tag must appear in image caption (Stored XSS vulnerability)"
  end
end
