# frozen_string_literal: true

require "test_helper"
require_relative "e2e_helper"
require "tempfile"

class UnsafeFileUploadTest < ActiveSupport::TestCase
  include E2EHelper

  setup do
    @safe_server = ServerProcess.new(port: 4090, vuln_challenges: "")
    @vuln_server = ServerProcess.new(port: 4091, vuln_challenges: "unsafe_file_upload")
    @safe_server.start!
    @vuln_server.start!
  end

  teardown do
    @safe_server.stop!
    @vuln_server.stop!
  end

  def upload_file(server, filename:, content:, content_type:)
    cookie = setup_session(server)

    res = server.get("/tasks/new", headers: { "Cookie" => cookie })
    cookie = latest_cookie(res, cookie)
    token = extract_csrf_token(res.body)

    # multipart/form-data を手動構築
    boundary = "----E2EBoundary#{SecureRandom.hex(8)}"
    body = String.new
    body << "--#{boundary}\r\n"
    body << "Content-Disposition: form-data; name=\"authenticity_token\"\r\n\r\n"
    body << "#{token}\r\n"
    body << "--#{boundary}\r\n"
    body << "Content-Disposition: form-data; name=\"task[title]\"\r\n\r\n"
    body << "Upload test\r\n"
    body << "--#{boundary}\r\n"
    body << "Content-Disposition: form-data; name=\"task[attachment]\"; filename=\"#{filename}\"\r\n"
    body << "Content-Type: #{content_type}\r\n\r\n"
    body << "#{content}\r\n"
    body << "--#{boundary}--\r\n"

    uri = URI("http://127.0.0.1:#{server.port}/tasks")
    req = Net::HTTP::Post.new(uri)
    req["Cookie"] = cookie
    req["Content-Type"] = "multipart/form-data; boundary=#{boundary}"
    req.body = body

    res = Net::HTTP.start(uri.host, uri.port) { |http| http.request(req) }
    { response: res, cookie: latest_cookie(res, cookie) }
  end

  test "SAFE: executable file upload is rejected" do
    result = upload_file(@safe_server,
      filename: "malware.exe",
      content: "MZ\x90\x00",  # PE header
      content_type: "application/x-msdownload"
    )
    # バリデーション失敗 -> 422
    assert_equal "422", result[:response].code,
      "Executable file should be rejected by MIME whitelist"
  end

  test "SAFE: image file upload is accepted" do
    result = upload_file(@safe_server,
      filename: "photo.png",
      content: "\x89PNG\r\n\x1a\n",
      content_type: "image/png"
    )
    assert_equal "302", result[:response].code, "PNG file should be accepted"
  end

  test "VULN: executable file upload is accepted (no validation)" do
    result = upload_file(@vuln_server,
      filename: "malware.exe",
      content: "MZ\x90\x00",
      content_type: "application/x-msdownload"
    )
    assert_equal "302", result[:response].code,
      "Executable file should be accepted (unsafe file upload vulnerability)"
  end
end
