# frozen_string_literal: true

require "open-uri"

module Vulnerabilities
  module Challenges
    # チャレンジ20: SSRF via URL preview
    # 開発者が「Ruby標準のHTTPライブラリよりcurlの方がタイムアウト管理やリダイレクト処理が楽」
    # と判断して外部コマンドを叩いてしまった、という設定。
    class Ssrf < Base
      metadata do
        name        "SSRF via URL preview (CWE-918)"
        category    :ssrf
        difficulty  :medium
        description "URLプレビュー機能が、外部リクエストを発行する際に curl コマンドを使用しています。" \
                    "curl は http/https 以外にも多くのプロトコルをサポートしており、" \
                    "gopher:// スキームを悪用することで、内部の Redis などのサービスを攻撃可能です。"
        hint        "TasksController#preview_url のソースを確認してください。なぜわざわざ curl を叩いているのでしょうか？"
        hint        "curl --manual プロトコル のセクションを確認すると、サポートされているスキームが分かります。"
        hint        "gopher://redis:6379/_ に RESP エンコードした PING を送ると何が返りますか?"
        cwe         "CWE-918"
        reference   "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"
        slot        "TasksController#preview_url"
      end

      def apply!
        vuln_module = Module.new do
          def preview_url
            # 開発者の言い訳:
            # 「Ruby の Net::HTTP や open-uri はタイムアウトの設定が面倒だし、
            # リダイレクトの無限ループ対策なども考慮すると curl を使うのが一番手っ取り早い。
            # 5秒でタイムアウトするように設定してあるから、可用性もバッチリだ！」
            require 'shellwords'
            require 'open3'

            safe_url = Shellwords.escape(params[:url].to_s)
            
            # 脆弱性: 外部コマンド curl に丸投げしているため、http/https 以外のスキーム(gopher等)が通ってしまう。
            # 本来は --proto オプションでプロトコルを制限するか、URLのバリデーションが必要。
            stdout, stderr, status = Open3.capture3("curl -m 5 -s -L #{safe_url}")
            
            # バイナリデータが含まれる場合（Redis等）に備え、UTF-8として安全に扱えるように強制変換
            stdout = stdout.to_s.force_encoding('UTF-8').scrub('?')

            # Redis などの TCP サービスの場合、接続が閉じられないため curl はタイムアウト(exit 28)するが、
            # その時点までに受け取ったデータ(stdout)があれば、プレビューとしては「成功」扱いにした方が
            # 攻撃（情報の取得）が成立しやすくなる。
            if status.success? || (status.exitstatus == 28 && stdout.present?)
              # レスポンスから title を抽出しようとする（HTML以外だと失敗するがそれもリアリティ）
              title = stdout.match(/<title>(.*?)<\/title>/mi)&.captures&.first
              render json: { title: title || "(no title)", body: stdout.truncate(500) }
            else
              render json: { error: "Fetch failed (exit #{status.exitstatus}): #{stderr.truncate(100)}" }, status: :unprocessable_entity
            end
          rescue => e
            render json: { error: e.message }, status: :unprocessable_entity
          end
        end

        prepend_to TasksController, vuln_module

        # チャレンジ適用時のみ、意図的にセッションを Redis に保存するように設定変更
        # これにより SSRF -> Redis の攻撃対象（セッションデータ）が生まれる
        Rails.application.config.cache_store = :redis_cache_store, { url: ENV.fetch("REDIS_URL", "redis://redis:6379/1") }
        # Rails.cache を再初期化
        Rails.cache = ActiveSupport::Cache.lookup_store(Rails.application.config.cache_store)

        add_routes do
          post "/tasks/:id/preview_url", to: "tasks#preview_url", as: :preview_url_task
        end

        inject_view "tasks/_url_preview.html.erb", <<~ERB
          <% if @task.url.present? %>
            <div class="detail-row">
              <div class="label">URLプレビュー</div>
              <div>
                <%= form_with url: preview_url_task_path(@task), method: :post, local: true do |f| %>
                  <%= hidden_field_tag :url, @task.url %>
                  <%= f.submit "プレビュー取得", class: "btn btn-secondary" %>
                <% end %>
              </div>
            </div>
          <% end %>
        ERB
      end
    end
  end
end
