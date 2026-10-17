# frozen_string_literal: true

require "json"
require "minitest"
require "fileutils"
require "tmpdir"
require_relative "../../test/integration/vulnerabilities/e2e_helper"
require_relative "rails-harness"

if ARGV.first == "serve"
  servers = []
  children = []
  log_dir = File.expand_path("../../.e2e/logs", __dir__)
  trap("TERM") { exit }
  trap("INT") { exit }
  begin
    source = File.expand_path("../..", __dir__)
    [
      [3101, ""],
      [3102, "css_injection"],
      [3103, "xss_raw"],
      [3104, "xss_raw,csp_disable"],
      [3105, "xss_stored_img"],
      [3106, "xss_stored_img,csp_disable"]
    ].each do |port, challenges|
      root = Dir.mktmpdir("rails-e2e-")
      process_log = "/tmp/e2e_server_#{port}.log"
      servers << { root: root, port: port, process_log: process_log }
      FileUtils.rm_f(process_log)
      # Each Rails boot clears generated views, so servers need separate app roots.
      %w[app bin config db lib public vendor Gemfile Gemfile.lock Rakefile config.ru .ruby-version].each do |entry|
        path = File.join(source, entry)
        FileUtils.cp_r(path, root) if File.exist?(path)
      end
      FileUtils.mkdir_p([File.join(root, "log"), File.join(root, "tmp")])
      # SQLite and uploads are shared, so the two suites must run sequentially.
      FileUtils.ln_s(File.join(source, "storage"), File.join(root, "storage"))
      children << Process.spawn("bundle", "exec", "ruby", __FILE__, "server", root, port.to_s, challenges)
      RailsHarness.wait_for_server(port: port, challenges: challenges, pid: children.last,
        log_dir: log_dir, process_log: process_log)
    end
    sleep
  ensure
    children.each do |pid|
      begin
        Process.kill("TERM", pid)
      rescue Errno::ESRCH
        # Startup failure may already have stopped the child.
      end
    end
    children.each do |pid|
      begin
        Process.wait(pid)
      rescue Errno::ECHILD
        # The readiness check may already have collected its exit status.
      end
    end
    servers.each { |server| RailsHarness.cleanup_server(**server, log_dir: log_dir) }
  end
elsif ARGV.first == "server"
  root, port, challenges = ARGV.drop(1)
  ENV["VULN_CHALLENGES"] = challenges
  require File.join(root, "config/environment")
  server = E2EHelper::ServerProcess.new(port: Integer(port), vuln_challenges: challenges)
  trap("TERM") { exit }
  trap("INT") { exit }
  begin
    server.start!
    sleep
  ensure
    server.stop!
  end
elsif ARGV[2] == "image"
  require_relative "image-task"
  server = E2EHelper::ServerProcess.new(port: Integer(ARGV.fetch(0)))
  task = JSON.parse(ARGV.fetch(1), symbolize_names: true)
  helper = Object.new.extend(ImageTaskHelper)
  result = helper.create_image_task_with_description(server, **task)
  puts "E2E_DATA=#{JSON.generate(result)}"
else
  helper = Object.new.extend(E2EHelper)
  server = E2EHelper::ServerProcess.new(port: Integer(ARGV.fetch(0)))
  cookie = helper.setup_session(server)
  task = JSON.parse(ARGV.fetch(1), symbolize_names: true)
  result = helper.create_task_via_form(server, **task, cookie: cookie)
  abort "Task creation failed on port #{server.port}; inspect .e2e/logs/rails-#{server.port}-app.log" unless result[:id]
  puts "E2E_DATA=#{JSON.generate(result)}"
end
