# frozen_string_literal: true

require "net/http"
require "uri"
require "timeout"

# E2E テスト用ヘルパー
# 脆弱性 ON/OFF の別プロセスで Rails サーバーを起動し HTTP で検証する
module E2EHelper
  BASE_PORT = 4000

  class ServerProcess
    attr_reader :port, :pid

    def initialize(port:, vuln_challenges: "")
      @port = port
      @vuln_challenges = vuln_challenges
      @pid = nil
    end

    def start!
      env = {
        "RAILS_ENV" => "test",
        "VULN_CHALLENGES" => @vuln_challenges,
        "SECRET_KEY_BASE" => "test_secret_key_base_for_e2e_testing_only_1234567890",
      }
      log = "/tmp/e2e_server_#{@port}.log"
      pid_file = "/tmp/e2e_server_#{@port}.pid"
      FileUtils.rm_f(pid_file)
      @pid = Process.spawn(
        env,
        "bundle", "exec", "rails", "server",
        "-b", "127.0.0.1", "-p", @port.to_s,
        "-P", pid_file,
        chdir: Rails.root.to_s,
        [:out, :err] => log,
        pgroup: true
      )
      wait_for_ready!
    end

    def stop!
      return unless @pid
      # プロセスグループごと停止
      Process.kill("TERM", -Process.getpgid(@pid))
    rescue Errno::ESRCH, Errno::EPERM
      # already gone
    ensure
      Process.wait(@pid) rescue nil
      @pid = nil
    end

    def get(path, headers: {})
      uri = URI("http://127.0.0.1:#{@port}#{path}")
      req = Net::HTTP::Get.new(uri)
      headers.each { |k, v| req[k] = v }
      Net::HTTP.start(uri.host, uri.port) { |http| http.request(req) }
    end

    def post(path, body: "", headers: {})
      uri = URI("http://127.0.0.1:#{@port}#{path}")
      req = Net::HTTP::Post.new(uri)
      req["Content-Type"] = "application/x-www-form-urlencoded"
      headers.each { |k, v| req[k] = v }
      req.body = body
      Net::HTTP.start(uri.host, uri.port) do |http|
        http.max_retries = 0
        http.request(req)
      end
    end

    private

    def wait_for_ready!
      Timeout.timeout(30) do
        loop do
          res = Net::HTTP.get_response(URI("http://127.0.0.1:#{@port}/up"))
          break if res.code.to_i == 200
        rescue Errno::ECONNREFUSED, Errno::EADDRNOTAVAIL
          sleep 0.3
        end
      end
    end
  end

  # テスト用タスクを作成し id を返す
  def create_task_via_form(server, title:, description: "")
    # まず GET でフォームを取得して CSRF トークンを取る
    res = server.get("/tasks/new")
    token = extract_csrf_token(res.body)
    cookie = res["set-cookie"]&.split(";")&.first

    body = URI.encode_www_form(
      "authenticity_token" => token,
      "task[title]" => title,
      "task[description]" => description
    )
    headers = {}
    headers["Cookie"] = cookie if cookie

    post_res = server.post("/tasks", body: body, headers: headers)
    # 302 redirect to /tasks/:id
    if post_res["location"]
      post_res["location"].match(%r{/tasks/(\d+)})[1].to_i
    end
  end

  def extract_csrf_token(html)
    match = html.match(/name="authenticity_token"\s+value="([^"]+)"/)
    match[1] if match
  end
end
