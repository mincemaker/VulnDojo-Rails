# frozen_string_literal: true

require "test_helper"
require_relative "e2e_helper"

class RegexBypassTest < ActiveSupport::TestCase
  include E2EHelper

  # 改行を含む悪意あるURL: 1行目が javascript: 、2行目が http://...
  BYPASS_URL = "javascript:alert(1)\nhttp://legit.example.com"
  LEGIT_URL  = "https://example.com"

  setup do
    @safe_server = ServerProcess.new(port: 4080, vuln_challenges: "")
    @vuln_server = ServerProcess.new(port: 4081, vuln_challenges: "regex_bypass")
    @safe_server.start!
    @vuln_server.start!
  end

  teardown do
    @safe_server.stop!
    @vuln_server.stop!
  end

  def create_task_with_url(server, url:)
    cookie = setup_session(server)
    res = server.get("/tasks/new", headers: { "Cookie" => cookie })
    cookie = latest_cookie(res, cookie)
    token = extract_csrf_token(res.body)

    body = URI.encode_www_form(
      "authenticity_token" => token,
      "task[title]"        => "Regex test",
      "task[url]"          => url
    )
    res = server.post("/tasks", body: body, headers: { "Cookie" => cookie })
    cookie = latest_cookie(res, cookie)
    { response: res, cookie: cookie }
  end

  test "SAFE: multiline bypass URL is rejected by \\A anchor" do
    result = create_task_with_url(@safe_server, url: BYPASS_URL)
    # \A anchor rejects the javascript: scheme
    assert_equal "422", result[:response].code,
      "Multiline URL should be rejected by \\A anchor validation"
  end

  test "SAFE: legitimate URL is accepted" do
    result = create_task_with_url(@safe_server, url: LEGIT_URL)
    assert_equal "302", result[:response].code, "Legit URL should be accepted"
  end

  test "VULN: multiline bypass URL passes ^ anchor validation" do
    result = create_task_with_url(@vuln_server, url: BYPASS_URL)
    # ^ anchor matches the http:// on the second line
    assert_equal "302", result[:response].code,
      "Multiline URL should pass ^ anchor validation (regex bypass vulnerability)"
  end
end
