# frozen_string_literal: true

require "minitest/autorun"
require "tmpdir"
require "socket"
require "rbconfig"
require_relative "../../tests/support/rails-harness"

class RailsHarnessTest < Minitest::Test
  def test_cleanup_keeps_app_and_process_logs_after_removing_app_copy
    Dir.mktmpdir do |dir|
      root = File.join(dir, "app")
      logs = File.join(dir, "results")
      process_log = File.join(dir, "puma.log")
      FileUtils.mkdir_p(File.join(root, "log"))
      File.write(File.join(root, "log/test.log"), "Request failed with HTTP 500\n")
      File.write(process_log, "Puma failed to bind\n")

      RailsHarness.cleanup_server(root: root, port: 3101, log_dir: logs, process_log: process_log)

      refute File.exist?(root)
      assert File.exist?(File.join(logs, "rails-3101-app.log")), "Rails request log must survive cleanup"
      assert_equal "Request failed with HTTP 500\n", File.read(File.join(logs, "rails-3101-app.log"))
      assert_equal "Puma failed to bind\n", File.read(File.join(logs, "rails-3101-process.log"))
    end
  end

  def test_boot_failure_reports_child_exit_challenge_and_process_log
    Dir.mktmpdir do |dir|
      process_log = File.join(dir, "puma.log")
      File.write(process_log, "Broken initializer\n")
      listener = TCPServer.new("127.0.0.1", 0)
      port = listener.addr[1]
      listener.close
      pid = Process.spawn(RbConfig.ruby, "-e", "exit 17")

      error = assert_raises(RuntimeError) do
        RailsHarness.wait_for_server(port: port, challenges: "xss_raw", pid: pid,
          log_dir: dir, process_log: process_log, timeout: 2)
      end

      assert_includes error.message, "port #{port}"
      assert_includes error.message, "xss_raw"
      assert_includes error.message, "exit 17"
      assert_includes error.message, "Broken initializer"
    ensure
      begin
        Process.wait(pid) if pid
      rescue Errno::ECHILD
        # The readiness check collects the failed child's exit status.
      end
    end
  end
end
