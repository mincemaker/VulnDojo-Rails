# frozen_string_literal: true

require "test_helper"
require_relative "e2e_helper"

class CommandInjectionTest < ActiveSupport::TestCase
  include E2EHelper

  setup do
    @safe_server = ServerProcess.new(port: 4140, vuln_challenges: "")
    @vuln_server = ServerProcess.new(port: 4141, vuln_challenges: "command_injection")
    @safe_server.start!
    @vuln_server.start!
  end

  teardown do
    @safe_server.stop!
    @vuln_server.stop!
  end

  test "SAFE: name parameter does not affect filename via shell" do
    cookie = setup_session(@safe_server)
    # Create a task so export has data
    create_task_via_form(@safe_server, title: "Export test", cookie: cookie)

    res = @safe_server.get("/tasks/export.csv?name=$(whoami)", headers: { "Cookie" => cookie })
    assert_equal "200", res.code

    # Safe version ignores name param entirely
    content_disposition = res["content-disposition"]
    current_user = `whoami`.strip
    refute_match(/#{Regexp.escape(current_user)}/, content_disposition.to_s,
      "Shell command output should NOT appear in filename")
  end

  test "VULN: shell command is executed in filename generation" do
    cookie = setup_session(@vuln_server)
    create_task_via_form(@vuln_server, title: "Export test", cookie: cookie)

    # $(whoami) should be executed by the shell
    res = @vuln_server.get("/tasks/export.csv?name=$(whoami)", headers: { "Cookie" => cookie })
    assert_equal "200", res.code

    content_disposition = res["content-disposition"]
    # whoami returns the current user (e.g., "exedev")
    current_user = `whoami`.strip
    assert_match(/#{Regexp.escape(current_user)}/, content_disposition.to_s,
      "Shell command output should appear in filename (command injection vulnerability)")
  end
end
