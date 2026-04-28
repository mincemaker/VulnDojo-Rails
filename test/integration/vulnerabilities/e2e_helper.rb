# frozen_string_literal: true

require "net/http"
require "uri"
require "timeout"
require "securerandom"
require "socket"

# E2E テスト用ヘルパー
# 脆弱性 ON/OFF の別プロセスで Rails サーバーを起動し HTTP で検証する
module E2EHelper
  TEST_USER_PASSWORD = "password123"

  class ServerProcess
    attr_reader :port

    def initialize(port:, vuln_challenges: "", rails_env: "test")
      @port = port
      @vuln_challenges = vuln_challenges
      @rails_env = rails_env
      @pid = nil
    end

    def start!
      env = {
        "RAILS_ENV" => @rails_env,
        "VULN_CHALLENGES" => @vuln_challenges,
        "SECRET_KEY_BASE" => "test_secret_key_base_for_e2e_testing_only_1234567890",
      }
      system(env, "bundle", "exec", "rails", "db:prepare", chdir: Rails.root.to_s, exception: false)
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
      Process.kill("TERM", -Process.getpgid(@pid))
    rescue Errno::ESRCH, Errno::EPERM
    ensure
      Process.wait(@pid) rescue nil
      @pid = nil
    end

    # --- HTTP メソッド: cookie 自動追跡 ---

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

    def delete(path, headers: {})
      uri = URI("http://127.0.0.1:#{@port}#{path}")
      req = Net::HTTP::Delete.new(uri)
      headers.each { |k, v| req[k] = v }
      Net::HTTP.start(uri.host, uri.port) { |http| http.request(req) }
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

  # テスト用ユーザを作成してログインし、セッションCookieを返す
  def setup_session(server)
    suffix = "#{server.port}_#{SecureRandom.hex(6)}"
    email = "e2e_#{suffix}@example.com"
    name  = "tester_#{suffix}"

    # 1) GET /signup
    res1 = server.get("/signup")
    cookie = latest_cookie(res1)
    token = extract_csrf_token(res1.body)

    # 2) POST /signup
    body = URI.encode_www_form(
      "authenticity_token" => token,
      "user[name]"         => name,
      "user[email]"        => email,
      "user[password]"     => TEST_USER_PASSWORD,
      "user[password_confirmation]" => TEST_USER_PASSWORD
    )
    res2 = server.post("/signup", body: body, headers: { "Cookie" => cookie })
    cookie = latest_cookie(res2, cookie)

    if res2.code == "302"
      return cookie
    end

    # サインアップ失敗 → ログイン
    res3 = server.get("/login")
    cookie = latest_cookie(res3)
    token = extract_csrf_token(res3.body)

    body = URI.encode_www_form(
      "authenticity_token" => token,
      "email"     => email,
      "password"  => TEST_USER_PASSWORD
    )
    res4 = server.post("/login", body: body, headers: { "Cookie" => cookie })
    latest_cookie(res4, cookie)
  end

  # テスト用タスクを作成し id と cookie を返す
  def create_task_via_form(server, title:, description: "", color: nil, cookie: nil)
    cookie ||= setup_session(server)

    # GET /tasks/new
    res1 = server.get("/tasks/new", headers: { "Cookie" => cookie })
    cookie = latest_cookie(res1, cookie)

    if res1.code == "302"
      cookie = setup_session(server)
      res1 = server.get("/tasks/new", headers: { "Cookie" => cookie })
      cookie = latest_cookie(res1, cookie)
    end

    token = extract_csrf_token(res1.body)

    params_hash = {
      "authenticity_token" => token,
      "task[title]" => title,
      "task[description]" => description
    }
    params_hash["task[color]"] = color if color

    body = URI.encode_www_form(params_hash)

    res2 = server.post("/tasks", body: body, headers: { "Cookie" => cookie })
    cookie = latest_cookie(res2, cookie)

    task_id = nil
    if res2["location"]
      m = res2["location"].match(%r{/tasks/(\d+)})
      task_id = m[1].to_i if m
    end
    { id: task_id, cookie: cookie }
  end

  def extract_csrf_token(html)
    # 1) meta タグから取得を試みる (最も確実)
    # <meta name="csrf-token" content="..." />
    if html =~ /<meta name="csrf-token" content="([^"]+)"/
      return $1
    end

    # 2) フォームの hidden field から取得を試みる (フォールバック)
    # 属性の順序に依存しないように scan し、値だけを抽出する
    tokens = html.scan(/<input[^>]+name="authenticity_token"[^>]+value="([^"]+)"/)
    return tokens.last&.first if tokens.any?

    # 逆の順序 (value, name) も考慮
    tokens = html.scan(/<input[^>]+value="([^"]+)"[^>]+name="authenticity_token"/)
    tokens.last&.first
  end

  # レスポンスから最新のセッションcookieを取得。なければfallbackを返す。
  def latest_cookie(response, fallback = nil)
    raw = response["set-cookie"]
    if raw
      raw.split(";").first
    else
      fallback
    end
  end

  # テストスイート全体でサーバーインスタンスを共有するプール
  # VULN_CHALLENGES + rails_env の組み合わせで一意にキャッシュし、
  # 同一構成のサーバーは起動をスキップして再利用する
  class ServerPool
    @mutex = Mutex.new
    @servers = {}

    class << self
      def acquire(vuln_challenges: "", rails_env: "test")
        key = "#{vuln_challenges}|#{rails_env}"
        @mutex.synchronize do
          @servers[key] ||= begin
            port = allocate_port
            server = ServerProcess.new(port: port, vuln_challenges: vuln_challenges, rails_env: rails_env)
            server.start!
            server
          end
        end
      end

      def shutdown_all
        @mutex.synchronize do
          @servers.each_value(&:stop!)
          @servers.clear
        end
      end

      private

      def allocate_port
        server = TCPServer.new("127.0.0.1", 0)
        port = server.addr[1]
        server.close
        port
      end
    end
  end
end

Minitest.after_run { E2EHelper::ServerPool.shutdown_all }
