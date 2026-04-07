# frozen_string_literal: true

require "test_helper"
require_relative "e2e_helper"

class OpenRedirectTest < ActiveSupport::TestCase
  include E2EHelper

  EVIL_URL = "https://evil.example.com/phishing"

  setup do
    @safe_server = ServerProcess.new(port: 4040, vuln_challenges: "")
    @vuln_server = ServerProcess.new(port: 4041, vuln_challenges: "open_redirect")
    @safe_server.start!
    @vuln_server.start!
  end

  teardown do
    @safe_server.stop!
    @vuln_server.stop!
  end

  test "SAFE: external return_to is ignored, redirects to task" do
    cookie = setup_session(@safe_server)

    # GET /tasks/new to get CSRF token
    res1 = @safe_server.get("/tasks/new", headers: { "Cookie" => cookie })
    cookie = latest_cookie(res1, cookie)
    token = extract_csrf_token(res1.body)

    # POST /tasks with external return_to
    body = URI.encode_www_form(
      "authenticity_token" => token,
      "task[title]"        => "Safe redirect test",
      "return_to"          => EVIL_URL
    )
    res2 = @safe_server.post("/tasks", body: body, headers: { "Cookie" => cookie })

    assert_equal "302", res2.code, "Should redirect"
    location = res2["location"]
    refute_match(/evil\.example\.com/, location, "Must NOT redirect to external URL")
    assert_match(%r{/tasks/\d+}, location, "Should redirect to the created task")
  end

  test "VULN: external return_to causes open redirect" do
    cookie = setup_session(@vuln_server)

    # GET /tasks/new to get CSRF token
    res1 = @vuln_server.get("/tasks/new", headers: { "Cookie" => cookie })
    cookie = latest_cookie(res1, cookie)
    token = extract_csrf_token(res1.body)

    # POST /tasks with external return_to
    body = URI.encode_www_form(
      "authenticity_token" => token,
      "task[title]"        => "Vuln redirect test",
      "return_to"          => EVIL_URL
    )
    res2 = @vuln_server.post("/tasks", body: body, headers: { "Cookie" => cookie })

    assert_equal "302", res2.code, "Should redirect"
    location = res2["location"]
    assert_equal EVIL_URL, location, "Should redirect to external URL (open redirect vulnerability)"
  end

  test "SAFE: protocol-relative return_to is blocked" do
    cookie = setup_session(@safe_server)

    res1 = @safe_server.get("/tasks/new", headers: { "Cookie" => cookie })
    cookie = latest_cookie(res1, cookie)
    token = extract_csrf_token(res1.body)

    body = URI.encode_www_form(
      "authenticity_token" => token,
      "task[title]"        => "Protocol-relative test",
      "return_to"          => "//evil.example.com/phishing"
    )
    res2 = @safe_server.post("/tasks", body: body, headers: { "Cookie" => cookie })

    assert_equal "302", res2.code
    location = res2["location"]
    refute_match(/evil\.example\.com/, location, "Must NOT follow protocol-relative redirect")
  end
end
