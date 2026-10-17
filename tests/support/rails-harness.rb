# frozen_string_literal: true

require "fileutils"
require "net/http"

module RailsHarness
  module_function

  def cleanup_server(root:, port:, log_dir:, process_log:)
    FileUtils.mkdir_p(log_dir)
    {
      File.join(root, "log/test.log") => "rails-#{port}-app.log",
      process_log => "rails-#{port}-process.log"
    }.each do |source, name|
      FileUtils.cp(source, File.join(log_dir, name)) if File.file?(source)
    end
    FileUtils.remove_entry(root)
  end

  def wait_for_server(port:, challenges:, pid:, log_dir:, process_log:, timeout: 30)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    loop do
      if (exited = Process.waitpid2(pid, Process::WNOHANG))
        status = exited.last
        reason = status.exited? ? "child exit #{status.exitstatus}" : "child signal #{status.termsig}"
        startup_failure(port: port, challenges: challenges, reason: reason,
          log_dir: log_dir, process_log: process_log)
      end

      begin
        http = Net::HTTP.new("127.0.0.1", port, nil)
        http.open_timeout = http.read_timeout = 0.5
        return if http.get("/up").code == "200"
      rescue SystemCallError, IOError, Timeout::Error
        # The process may still be booting; its exit status is checked above.
      end

      break if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
      sleep 0.1
    end
    startup_failure(port: port, challenges: challenges, reason: "not ready after #{timeout}s",
      log_dir: log_dir, process_log: process_log)
  end

  def startup_failure(port:, challenges:, reason:, log_dir:, process_log:)
    tail = File.file?(process_log) ? File.readlines(process_log).last(20).join : "Process log not created."
    raise "Rails startup failed on port #{port}, VULN_CHALLENGES=#{challenges.inspect}: #{reason}\n" \
      "Logs: #{log_dir}/rails-#{port}-app.log and rails-#{port}-process.log\n#{tail}"
  end
end
