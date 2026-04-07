# frozen_string_literal: true

require "test_helper"
require_relative "e2e_helper"

class XssRawTest < ActiveSupport::TestCase
  include E2EHelper

  XSS_PAYLOAD = '<img src=x onerror=alert("XSS")>'

  setup do
    @safe_server = ServerProcess.new(port: 4010, vuln_challenges: "")
    @vuln_server = ServerProcess.new(port: 4011, vuln_challenges: "xss_raw")
    @safe_server.start!
    @vuln_server.start!
  end

  teardown do
    @safe_server.stop!
    @vuln_server.stop!
  end

  test "SAFE: XSS payload is escaped in show page" do
    result = create_task_via_form(@safe_server, title: XSS_PAYLOAD)
    assert result[:id], "Task should be created"

    res = @safe_server.get("/tasks/#{result[:id]}", headers: { "Cookie" => result[:cookie] })
    body = res.body

    assert_includes body, "&lt;img", "XSS payload must be HTML-escaped"
    refute_includes body, '<img src=x onerror', "Raw HTML tag must NOT appear"
  end

  test "VULN: XSS payload is rendered as raw HTML in show page" do
    result = create_task_via_form(@vuln_server, title: XSS_PAYLOAD)
    assert result[:id], "Task should be created"

    res = @vuln_server.get("/tasks/#{result[:id]}", headers: { "Cookie" => result[:cookie] })
    body = res.body

    assert_includes body, '<img src=x onerror', "Raw HTML tag must appear (XSS vulnerability)"
  end
end
