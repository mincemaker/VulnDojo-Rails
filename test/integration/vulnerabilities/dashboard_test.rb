# frozen_string_literal: true

require "test_helper"

class VulnerabilitiesDashboardTest < ActionDispatch::IntegrationTest
  setup do
    ActionController::Base.allow_forgery_protection = false
    @user = User.create!(name: "dash_test", email: "dash_test@example.com", password: "password1234")
    post login_path, params: { email: @user.email, password: "password1234" }

    @registry = Vulnerabilities::Registry.instance
    @saved = @registry.active_slugs

    @registry.all_challenges.keys.each { |slug| @registry.disable(slug) }
    @registry.enable("xss_reflected")
    @registry.enable("sql_injection_active_record")
  end

  teardown do
    @registry.all_challenges.keys.each { |slug| @registry.disable(slug) }
    @saved.each { |slug| @registry.enable(slug) }
    ActionController::Base.allow_forgery_protection = true
  end

  test "renders exact active slugs in VULN_CHALLENGES code element" do
    get vulnerabilities_dashboard_path
    assert_response :success

    assert_select "code[style]",
      text: "VULN_CHALLENGES=xss_reflected,sql_injection_active_record bin/rails server"
  end
end
