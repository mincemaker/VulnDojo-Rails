# frozen_string_literal: true

require "test_helper"
require_relative "e2e_helper"

class BrokenAuthTimingTest < ActiveSupport::TestCase
  include E2EHelper

  # Timing Attack on Login 検証戦略:
  # Safe 実装 (authenticate_by) はユーザーが存在しない場合もダミー bcrypt を実行し、
  # 定数時間を保証する。VULN 実装は「unless user; return; end」で即 return するため、
  # 存在しないユーザーへのレスポンスが明らかに速くなる（CWE-208）。
  #
  # 計測方法:
  # - ウォームアップ 3 回 + 計測 15 回
  # - min で比較（ネットワークやGCのスパイクを除去し、ベースラインを計測）
  # - SAFE: nonexisting / existing > 0.4（authenticate_by のダミー bcrypt で時間が揃う）
  # - VULN: nonexisting / existing < 0.25（bcrypt スキップで明確に速い）

  WARMUP_COUNT  = 3
  MEASURE_COUNT = 15

  setup do
    @safe_server = ServerPool.acquire(vuln_challenges: "")
    @vuln_server = ServerPool.acquire(vuln_challenges: "broken_auth_timing")
  end

  # 存在するユーザーを作成し、email と password を返す
  def create_user(server)
    suffix = "#{server.port}_#{SecureRandom.hex(4)}"
    email    = "timing_#{suffix}@example.com"
    name     = "timing_#{suffix}"
    password = TEST_USER_PASSWORD

    res   = server.get("/signup")
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
    res   = server.get("/login")
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

  test "SAFE: existing and missing user response times are comparable (bcrypt always runs)" do
    user = create_user(@safe_server)
    existing_email = user[:email]
    missing_email  = "no_such_user_#{SecureRandom.hex(8)}@example.com"
    wrong_password = "wrongpassword!"

    existing_times = collect_times(@safe_server, existing_email, wrong_password)
    missing_times  = collect_times(@safe_server, missing_email,  wrong_password)

    existing_min = existing_times.min
    missing_min  = missing_times.min
    ratio = missing_min / existing_min

    assert ratio > 0.4,
      "SAFE: missing user should be within 2.5x of existing user time " \
      "(ratio=#{ratio.round(3)}, existing=#{existing_min.round(3)}s, missing=#{missing_min.round(3)}s). " \
      "authenticate_by should run dummy bcrypt for missing users."
  end

  test "VULN: missing user response is significantly faster (bcrypt skipped)" do
    user = create_user(@vuln_server)
    existing_email = user[:email]
    missing_email  = "no_such_user_#{SecureRandom.hex(8)}@example.com"
    wrong_password = "wrongpassword!"

    existing_times = collect_times(@vuln_server, existing_email, wrong_password)
    missing_times  = collect_times(@vuln_server, missing_email,  wrong_password)

    existing_min = existing_times.min
    missing_min  = missing_times.min
    ratio = missing_min / existing_min

    assert ratio < 0.25,
      "VULN: missing user should be at least 4x faster than existing user " \
      "(ratio=#{ratio.round(3)}, existing=#{existing_min.round(3)}s, missing=#{missing_min.round(3)}s). " \
      "bcrypt is skipped when user not found."
  end
end

# User.singleton_class への prepend_to 冪等性を検証する
# broken_auth_timing は prepend_to(User.singleton_class, ...) を使う初めてのチャレンジであり、
# apply! を複数回呼んでも singleton_class の ancestors に重複しないことを確認する
class BrokenAuthTimingSingletonPrependIdempotencyTest < ActiveSupport::TestCase
  SLUG = Vulnerabilities::Challenges::BrokenAuthTiming.slug

  test "apply! called twice does not double-prepend to User.singleton_class" do
    challenge = Vulnerabilities::Challenges::BrokenAuthTiming.new
    challenge.apply!
    challenge.apply!

    count = User.singleton_class.ancestors.count { |a|
      a.instance_variable_get(:@vuln_slug) == SLUG
    }
    assert_equal 1, count,
      "User.singleton_class に #{SLUG} モジュールが #{count} 回 prepend されている（期待: 1）"
  end
end
