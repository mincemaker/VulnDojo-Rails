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
        # Task モデルのバリデーションを緩和する
        # (開発者が外部サービスとの連携のために、うっかりスキーム制限のない正規表現に変えてしまった、という設定)
        Task.clear_validators!
        Task.validates :title, presence: true
        Task.validates :url, format: { with: /.*/ }, allow_blank: true

        vuln_module = Module.new do
          def show
            # プレビュー表示に必要なインラインJSのみを許可するため、
            # このアクションのCSPポリシーにのみ 'unsafe-inline' を追加する
            # (開発者がUIの動作を優先して最小限の緩和を行った、という設定)
            if request.content_security_policy
              request.content_security_policy.script_src(:self, :unsafe_inline)
            end
            super
          end

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
                <button id="fetch-preview-btn-<%= @task.id %>" 
                        onclick="if(window.runPreview) { runPreview('<%= @task.id %>', '<%= preview_url_task_path(@task) %>', '<%= @task.url %>') } else { alert('Initializing... please try again.') }"
                        class="btn btn-secondary btn-sm">プレビュー表示</button>
                
                <dialog id="preview-dialog-<%= @task.id %>" style="margin: auto; padding: 20px; border-radius: 8px; border: 1px solid #ccc; max-width: 600px; width: 100%; box-shadow: 0 4px 20px rgba(0,0,0,0.2);">
                  <style>
                    #preview-dialog-<%= @task.id %>::backdrop { background: rgba(0,0,0,0.5); }
                  </style>
                  <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; border-bottom: 1px solid #eee; padding-bottom: 10px;">
                    <h3 style="margin: 0;">プレビュー結果</h3>
                    <button onclick="this.closest('dialog').close()" class="btn btn-secondary btn-sm">閉じる</button>
                  </div>
                  <div id="preview-loading-<%= @task.id %>" style="display: none; color: #666; padding: 20px; text-align: center;">読み込み中...</div>
                  <div id="preview-content-<%= @task.id %>" style="display: none;">
                    <h4 id="preview-title-<%= @task.id %>" style="margin-bottom: 8px; color: #2563eb; word-break: break-all;"></h4>
                    <pre id="preview-body-<%= @task.id %>" style="background: #f8f9fa; padding: 12px; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; font-size: 0.9rem; max-height: 300px; overflow-y: auto; border: 1px solid #e5e7eb;"></pre>
                  </div>
                  <div id="preview-error-<%= @task.id %>" style="display: none; color: #dc2626; padding: 12px; background: #fee2e2; border-radius: 4px; border: 1px solid #fca5a5;"></div>
                </dialog>

                <script>
                  window.runPreview = async (taskId, previewPath, taskUrl) => {
                    const dialog = document.getElementById(`preview-dialog-${taskId}`);
                    const loadingDiv = document.getElementById(`preview-loading-${taskId}`);
                    const contentDiv = document.getElementById(`preview-content-${taskId}`);
                    const errorDiv = document.getElementById(`preview-error-${taskId}`);
                    const titleEl = document.getElementById(`preview-title-${taskId}`);
                    const bodyEl = document.getElementById(`preview-body-${taskId}`);

                    if (!dialog) return;
                    
                    dialog.showModal();
                    loadingDiv.style.display = 'block';
                    contentDiv.style.display = 'none';
                    errorDiv.style.display = 'none';
                    
                    try {
                      const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
                      const res = await fetch(previewPath, {
                        method: 'POST',
                        headers: { 
                          'Content-Type': 'application/json',
                          'X-CSRF-Token': csrfToken || ''
                        },
                        body: JSON.stringify({ url: taskUrl })
                      });
                      
                      const json = await res.json();
                      loadingDiv.style.display = 'none';
                      
                      if (res.ok) {
                        contentDiv.style.display = 'block';
                        titleEl.textContent = json.title || "(no title)";
                        bodyEl.textContent = json.body || "";
                      } else {
                        errorDiv.style.display = 'block';
                        errorDiv.textContent = json.error || "プレビューの取得に失敗しました";
                      }
                    } catch (err) {
                      loadingDiv.style.display = 'none';
                      errorDiv.style.display = 'block';
                      errorDiv.textContent = "通信エラーが発生しました";
                    }
                  };
                </script>
              </div>
            </div>
          <% end %>
        ERB
      end
    end
  end
end
