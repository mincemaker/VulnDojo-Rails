# frozen_string_literal: true

require "open-uri"

module Vulnerabilities
  module Challenges
    # チャレンジ20: SSRF via URL preview
    # URLプレビューアクションが open-uri で無検証リクエストを発行する。
    # gopher:// スキームを使えば Redis に RESP コマンドを直接送り込める。
    class Ssrf < Base
      metadata do
        name        "SSRF via URL preview (CWE-918)"
        category    :ssrf
        difficulty  :medium
        description "URLプレビュー機能がサーバー側で検証なしにリクエストを発行します。" \
                    "open-uri は gopher:// スキームをサポートしており、Redisへの直接コマンド送信が可能です。"
        hint        "タスクのURLプレビューエンドポイント (POST /tasks/:id/preview_url) を探してください"
        hint        "http://127.0.0.1:PORT/up など内部 HTTP エンドポイントに到達できますか?"
        hint        "gopher://redis:6379/_ に RESP エンコードした PING を送ると何が返りますか?"
        cwe         "CWE-918"
        reference   "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"
        slot        "TasksController#preview_url"
      end

      def apply!
        vuln_module = Module.new do
          def preview_url
            raw = URI.open(params[:url].to_s, &:read) # 脆弱性: open-uri で無検証リクエスト
            title = raw.match(/<title>(.*?)<\/title>/mi)&.captures&.first
            render json: { title: title || "(no title)", body: raw.to_s.truncate(500) }
          rescue => e
            render json: { error: e.message }, status: :unprocessable_entity
          end
        end

        prepend_to TasksController, vuln_module

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
