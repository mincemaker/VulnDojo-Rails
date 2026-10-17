# frozen_string_literal: true

# 脆弱性診断学習用モジュールの初期化
# 起動時に VULN_CHALLENGES 環境変数で指定された脆弱性を注入する
#
# 例:
#   VULN_CHALLENGES=xss_raw,sql_injection bin/rails server
#   VULN_CHALLENGES=csrf_skip bin/rails server
#   VULN_CHALLENGES=xss_raw,sql_injection,csrf_skip bin/rails server
#
# 設定しない場合は脆弱性なし（安全な状態）で起動

require_relative "../../lib/vulnerabilities/engine"

# チャレンジをロード・登録・有効化（起動時に1回、applyはしない）
Vulnerabilities::Engine.setup!

# セッション用ミドルウェアが保存先を保持する前に Redis へ切り替える。
if Vulnerabilities::Registry.instance.enabled?("ssrf")
  Rails.application.config.cache_store = :redis_cache_store, { url: ENV.fetch("REDIS_URL", "redis://redis:6379/1") }
  Rails.cache = ActiveSupport::Cache.lookup_store(Rails.application.config.cache_store)
end

# development 環境ではクラスがリロードされるため、
# to_prepare で毎回適用する（コントローラがロード済みのタイミング）
Rails.application.config.to_prepare do
  Vulnerabilities::Registry.instance.apply_all!
end
