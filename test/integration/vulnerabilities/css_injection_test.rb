# frozen_string_literal: true

require "test_helper"
require_relative "e2e_helper"

class CssInjectionTest < ActiveSupport::TestCase
  include E2EHelper

  CSS_PAYLOAD = "background:red; color:white"

  setup do
    @safe_server = ServerProcess.new(port: 4110, vuln_challenges: "")
    @vuln_server = ServerProcess.new(port: 4111, vuln_challenges: "css_injection")
    @safe_server.start!
    @vuln_server.start!
  end

  teardown do
    @safe_server.stop!
    @vuln_server.stop!
  end

  test "SAFE: description is not embedded in style attribute" do
    result = create_task_via_form(@safe_server, title: "CSS test", description: CSS_PAYLOAD)
    assert result[:id]

    res = @safe_server.get("/tasks/#{result[:id]}", headers: { "Cookie" => result[:cookie] })
    # 安全なテンプレートでは description が style 属性に埋め込まれない
    refute_match(/style="background:red/, res.body,
      "Description should NOT appear in a style attribute")
  end

  test "VULN: description is embedded in style attribute (CSS injection)" do
    result = create_task_via_form(@vuln_server, title: "CSS test", description: CSS_PAYLOAD)
    assert result[:id]

    res = @vuln_server.get("/tasks/#{result[:id]}", headers: { "Cookie" => result[:cookie] })
    assert_match(/style="background:red/, res.body,
      "Description should appear in style attribute (CSS injection vulnerability)")
  end
end
