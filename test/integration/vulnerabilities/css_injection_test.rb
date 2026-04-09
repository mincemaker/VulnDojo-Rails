# frozen_string_literal: true

require "test_helper"
require_relative "e2e_helper"

class CssInjectionTest < ActiveSupport::TestCase
  include E2EHelper

  CSS_PAYLOAD = "red; background:blue"

  setup do
    @safe_server = ServerPool.acquire(vuln_challenges: "")
    @vuln_server = ServerPool.acquire(vuln_challenges: "css_injection")
  end

  test "SAFE: color is not embedded unvalidated in style attribute" do
    result = create_task_via_form(@safe_server, title: "CSS test", color: CSS_PAYLOAD)
    assert result[:id]

    res = @safe_server.get("/tasks/#{result[:id]}", headers: { "Cookie" => result[:cookie] })
    # 安全なテンプレートでは不正なカラー値が style 属性に埋め込まれない
    # (#rrggbb 形式でないため match? が false となりスパンが非表示)
    refute_match(/border-left: 4px solid #{CSS_PAYLOAD}/, res.body,
      "Injected CSS should NOT appear unescaped in style attribute")
  end

  test "VULN: color is embedded unvalidated in style attribute (CSS injection)" do
    result = create_task_via_form(@vuln_server, title: "CSS test", color: CSS_PAYLOAD)
    assert result[:id]

    res = @vuln_server.get("/tasks/#{result[:id]}", headers: { "Cookie" => result[:cookie] })
    assert_match(/border-left: 4px solid #{CSS_PAYLOAD}/, res.body,
      "Injected CSS should appear in style attribute (CSS injection vulnerability)")
  end
end
