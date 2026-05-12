# frozen_string_literal: true

require "test_helper"
require_relative "e2e_helper"

class VulnerabilitiesDashboardE2eTest < ActiveSupport::TestCase
  include E2EHelper

  setup do
    @safe_server = ServerPool.acquire(vuln_challenges: "")
    @vuln_server = ServerPool.acquire(vuln_challenges: "xss_reflected,sql_injection_active_record")
  end

  test "SAFE: VULN_CHALLENGES is empty when no challenges enabled" do
    cookie = setup_session(@safe_server)
    res = @safe_server.get("/vulnerabilities", headers: { "Cookie" => cookie })

    slugs = res.body[/VULN_CHALLENGES=(.*?) bin\/rails server/, 1]
    assert_equal "", slugs
  end

  test "VULN: VULN_CHALLENGES shows exact enabled challenge slugs" do
    cookie = setup_session(@vuln_server)
    res = @vuln_server.get("/vulnerabilities", headers: { "Cookie" => cookie })

    slugs = res.body[/VULN_CHALLENGES=(.+?) bin\/rails server/, 1]
    assert_equal "xss_reflected,sql_injection_active_record", slugs
  end
end
