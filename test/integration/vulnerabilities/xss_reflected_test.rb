# frozen_string_literal: true

require "test_helper"
require_relative "e2e_helper"

class XssReflectedTest < ActiveSupport::TestCase
  include E2EHelper

  XSS_PAYLOAD = '<script>alert("XSS")</script>'

  setup do
    @safe_server = ServerProcess.new(port: 4030, vuln_challenges: "")
    @vuln_server = ServerProcess.new(port: 4031, vuln_challenges: "xss_reflected")
    @safe_server.start!
    @vuln_server.start!
  end

  teardown do
    @safe_server.stop!
    @vuln_server.stop!
  end

  test "SAFE: XSS payload in search query is escaped" do
    cookie = setup_session(@safe_server)
    res = @safe_server.get("/tasks?q=#{CGI.escape(XSS_PAYLOAD)}",
                           headers: { "Cookie" => cookie })

    assert_includes res.body, "&lt;script&gt;", "XSS payload must be HTML-escaped"
    refute_includes res.body, "<script>alert", "Raw script tag must NOT appear"
  end

  test "VULN: XSS payload in search query is reflected as raw HTML" do
    cookie = setup_session(@vuln_server)
    res = @vuln_server.get("/tasks?q=#{CGI.escape(XSS_PAYLOAD)}",
                           headers: { "Cookie" => cookie })

    assert_includes res.body, "<script>alert", "Raw script tag must appear (XSS vulnerability)"
  end
end
