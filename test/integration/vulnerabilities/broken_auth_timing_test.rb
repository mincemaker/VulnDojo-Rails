# frozen_string_literal: true

require "test_helper"
require_relative "e2e_helper"

class BrokenAuthTimingTest < ActiveSupport::TestCase
  include E2EHelper

  # Timing Attack on Login 検証戦略:
  # ブランチ scanner-test/all-vulns では脆弱性が app/ に直接ベイクドインされているため、
  # VULN_CHALLENGES なしでも脆弱な挙動が再現される。
  # コントローラは User.find_by → ユーザー不在時に bcrypt をスキップして即 return する（CWE-208）。
  #
  # 計測方法:
  # - ウォームアップ 3 回 + 計測 15 回
  # - min で比較（ネットワークやGCのスパイクを除去し、ベースラインを計測）
  # - 存在しないユーザー / 存在するユーザー の応答時間比 < 0.25（bcrypt スキップで明確に速い）

  WARMUP_COUNT  = 3
  MEASURE_COUNT = 15

  setup do
    @server = ServerPool.acquire(vuln_challenges: "")
  end

  # 存在するユーザーを作成し、email と password を返す
  def create_user(server)
    suffix = "#{server.port}_#{SecureRandom.hex(4)}"
    email    = "timing_#{suffix}@example.com"
    name     = "timing_#{suffix}"
    password = TEST_USER_PASSWORD

    res    = server.get("/signup")
    cookie = latest_cookie(res)
    token  = extract_csrf_token(res.body)
    body   = URI.encode_www_form(
      "authenticity_token"          => token,
      "user[name]"                  => name,
      "user[email]"                 => email,
      "user[password]"              => password,
      "user[password_confirmation]" => password
    )
    server.post("/signup", body: body, headers: { "Cookie" => cookie })

    { email: email, password: password }
  end

  # POST /login を1回実行し、秒単位の応答時間を返す
  def measure_login(server, email, password)
    res    = server.get("/login")
    cookie = latest_cookie(res)
    token  = extract_csrf_token(res.body)
    body   = URI.encode_www_form(
      "authenticity_token" => token,
      "email"              => email,
      "password"           => password
    )
    t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    server.post("/login", body: body, headers: { "Cookie" => cookie })
    Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0
  end

  def collect_times(server, email, password)
    WARMUP_COUNT.times { measure_login(server, email, password) }
    MEASURE_COUNT.times.map { measure_login(server, email, password) }
  end

  test "missing user response is significantly faster (bcrypt skipped)" do
    user = create_user(@server)
    existing_email = user[:email]
    missing_email  = "no_such_user_#{SecureRandom.hex(8)}@example.com"
    wrong_password = "wrongpassword!"

    existing_times = collect_times(@server, existing_email, wrong_password)
    missing_times  = collect_times(@server, missing_email,  wrong_password)

    existing_min = existing_times.min
    missing_min  = missing_times.min
    ratio = missing_min / existing_min

    assert ratio < 0.25,
      "missing user should be at least 4x faster than existing user " \
      "(ratio=#{ratio.round(3)}, existing=#{existing_min.round(3)}s, missing=#{missing_min.round(3)}s). " \
      "bcrypt is skipped when user not found."
  end
end
