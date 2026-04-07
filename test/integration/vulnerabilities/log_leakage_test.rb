# frozen_string_literal: true

require "test_helper"
require_relative "e2e_helper"

class LogLeakageTest < ActiveSupport::TestCase
  include E2EHelper

  SECRET_VALUE = "TOP_SECRET_NOTE_12345"

  setup do
    # development 環境で起動することでログ出力を有効化
    @safe_server = ServerProcess.new(port: 4100, vuln_challenges: "", rails_env: "development")
    @vuln_server = ServerProcess.new(port: 4101, vuln_challenges: "log_leakage", rails_env: "development")
    @safe_server.start!
    @vuln_server.start!
  end

  teardown do
    @safe_server.stop!
    @vuln_server.stop!
  end

  def create_task_with_secret(server)
    cookie = setup_session(server)
    res = server.get("/tasks/new", headers: { "Cookie" => cookie })
    cookie = latest_cookie(res, cookie)
    token = extract_csrf_token(res.body)

    body = URI.encode_www_form(
      "authenticity_token" => token,
      "task[title]"        => "Log test",
      "task[secret_note]"  => SECRET_VALUE
    )
    server.post("/tasks", body: body, headers: { "Cookie" => cookie })
  end

  test "SAFE: secret_note is filtered in logs" do
    create_task_with_secret(@safe_server)
    log = File.read("/tmp/e2e_server_#{@safe_server.port}.log")
    refute_includes log, SECRET_VALUE,
      "secret_note should be filtered (shown as [FILTERED])"
  end

  test "VULN: secret_note is visible in logs" do
    create_task_with_secret(@vuln_server)
    log = File.read("/tmp/e2e_server_#{@vuln_server.port}.log")
    assert_includes log, SECRET_VALUE,
      "secret_note should be visible in logs (log leakage vulnerability)"
  end
end
