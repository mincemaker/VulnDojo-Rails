# frozen_string_literal: true

require "test_helper"
require_relative "e2e_helper"

class CspDisableTest < ActiveSupport::TestCase
  include E2EHelper

  setup do
    @safe_server = ServerPool.acquire(vuln_challenges: "")
    @vuln_server = ServerPool.acquire(vuln_challenges: "csp_disable")
  end

  test "SAFE: Content-Security-Policy header is present" do
    cookie = setup_session(@safe_server)
    res = @safe_server.get("/tasks", headers: { "Cookie" => cookie })

    assert_equal "200", res.code
    csp = res["content-security-policy"]
    assert csp, "CSP header should be present"
    assert_match(/default-src/, csp, "CSP should include default-src directive")
    assert_match(/script-src/, csp, "CSP should include script-src directive")
  end

  test "VULN: Content-Security-Policy header is missing" do
    cookie = setup_session(@vuln_server)
    res = @vuln_server.get("/tasks", headers: { "Cookie" => cookie })

    assert_equal "200", res.code
    csp = res["content-security-policy"]
    assert_nil csp, "CSP header should be missing (CSP disabled vulnerability)"
  end
end
