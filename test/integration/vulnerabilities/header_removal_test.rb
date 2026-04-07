# frozen_string_literal: true

require "test_helper"
require_relative "e2e_helper"

class HeaderRemovalTest < ActiveSupport::TestCase
  include E2EHelper

  setup do
    @safe_server = ServerProcess.new(port: 4120, vuln_challenges: "")
    @vuln_server = ServerProcess.new(port: 4121, vuln_challenges: "header_removal")
    @safe_server.start!
    @vuln_server.start!
  end

  teardown do
    @safe_server.stop!
    @vuln_server.stop!
  end

  test "SAFE: security headers are present" do
    cookie = setup_session(@safe_server)
    res = @safe_server.get("/tasks", headers: { "Cookie" => cookie })

    assert_equal "200", res.code
    assert res["x-frame-options"], "X-Frame-Options should be present"
    assert res["x-content-type-options"], "X-Content-Type-Options should be present"
  end

  test "VULN: security headers are missing" do
    cookie = setup_session(@vuln_server)
    res = @vuln_server.get("/tasks", headers: { "Cookie" => cookie })

    assert_equal "200", res.code
    assert_nil res["x-frame-options"],
      "X-Frame-Options should be missing (header removal vulnerability)"
    assert_nil res["x-content-type-options"],
      "X-Content-Type-Options should be missing (header removal vulnerability)"
  end
end
