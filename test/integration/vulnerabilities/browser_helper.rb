# frozen_string_literal: true

require "ferrum"
require_relative "e2e_helper"

# ブラウザテスト用ヘルパー
# Ferrum (Chrome DevTools Protocol) でヘッドレス Chromium を操作し、
# JS 実行・CSS 計算値・DOM 状態をブラウザレベルで検証する
module BrowserHelper
  include E2EHelper

  CHROMIUM_PATH = "/usr/bin/chromium"

  def browser_setup
    @browser = BrowserPool.acquire
  end

  def browser_teardown
    @browser&.cookies&.clear
    @browser = nil
  end

  # Net::HTTP で取得したセッション Cookie をブラウザに注入して認証済み状態にする
  # setup_session が返す "_session_id=xxx" 形式の文字列を CDP の setCookie に変換する
  def browser_login(server)
    cookie_str = setup_session(server)
    name, value = cookie_str.split("=", 2)
    @browser.cookies.set(name: name, value: value, domain: "127.0.0.1", path: "/")
    cookie_str
  end

  # XSS 確認用ペイロード: onerror で window.__xss フラグを立てる
  # alert() ではなくフラグを使う理由:
  #   headless Chromium でダイアログキャプチャはタイミング問題が生じやすい。
  #   browser.evaluate("!!window.__xss") は goto 完了後に同期的に確認できる。
  XSS_FLAG_PAYLOAD = '<img src=x onerror="window.__xss=true">'

  def xss_executed?
    @browser.evaluate("!!window.__xss")
  end

  # テストスイート全体で Ferrum ブラウザインスタンスを共有するプール
  class BrowserPool
    @mutex = Mutex.new
    @browser = nil

    class << self
      def acquire
        @mutex.synchronize do
          @browser ||= Ferrum::Browser.new(
            headless: true,
            browser_path: CHROMIUM_PATH,
            browser_options: { "no-sandbox": nil, "disable-dev-shm-usage": nil },
            timeout: 15,
            process_timeout: 20,
          )
        end
      end

      def shutdown
        @mutex.synchronize do
          @browser&.quit
          @browser = nil
        end
      end
    end
  end
end

Minitest.after_run { BrowserHelper::BrowserPool.shutdown }
