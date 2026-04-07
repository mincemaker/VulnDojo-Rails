# frozen_string_literal: true

module Vulnerabilities
  module Challenges
    # チャレンジ2: SQL Injection
    # 検索機能を追加し、文字列補間で脆弱なSQLを実行する
    class SqlInjection < Base
      metadata do
        name        "SQL Injection via search"
        category    :injection
        difficulty  :medium
        description "タスク検索機能に SQL インジェクションの脆弱性があります。"
        hint        "検索パラメータの処理方法を確認してください"
        hint        "' OR 1=1-- を検索ボックスに入れてみましょう"
        cwe         "CWE-89"
        reference   "https://guides.rubyonrails.org/security.html#sql-injection"
      end

      def apply!
        # index アクションを上書きして脆弱な検索を注入
        vuln_module = Module.new do
          def index
            if params[:q].present?
              # ↓ 脆弱性: 文字列補間による SQL インジェクション
              @tasks = Task.where("title LIKE '%#{params[:q]}%'")
            else
              @tasks = Task.all
            end
          end
        end
        prepend_to TasksController, vuln_module

        inject_search_into_index!
      end

      private

      def inject_search_into_index!
        vuln_view_path = Rails.root.join("lib/vulnerabilities/views")
        FileUtils.mkdir_p(vuln_view_path.join("tasks"))

        # 検索ボックス付き index
        template = <<~'ERB'
          <div class="top-bar">
            <h2>タスク一覧</h2>
            <%= link_to "\u2795 \u65b0\u898f\u4f5c\u6210", new_task_path, class: "btn btn-primary" %>
          </div>

          <div class="card" style="margin-bottom: 16px;">
            <%= form_with(url: tasks_path, method: :get, local: true) do |f| %>
              <div style="display:flex; gap:8px;">
                <%= f.text_field :q, value: params[:q], placeholder: "\u30bf\u30b9\u30af\u3092\u691c\u7d22...", style: "flex:1; padding:8px 12px; border:1px solid #d1d5db; border-radius:6px; font-size:1rem;" %>
                <%= f.submit "\u691c\u7d22", class: "btn btn-primary" %>
              </div>
            <% end %>
          </div>

          <% if @tasks.any? %>
            <table>
              <thead>
                <tr>
                  <th>タイトル</th>
                  <th>状態</th>
                  <th>期限</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                <% @tasks.order(created_at: :desc).each do |task| %>
                  <tr>
                    <td><%= link_to task.title, task_path(task) %></td>
                    <td>
                      <% if task.completed? %>
                        <span class="badge badge-done">✅ 完了</span>
                      <% else %>
                        <span class="badge badge-todo">⏳ 未完了</span>
                      <% end %>
                    </td>
                    <td><%= task.due_date&.strftime("%Y-%m-%d") || "\u2014" %></td>
                    <td>
                      <div class="actions">
                        <%= link_to "\u7de8\u96c6", edit_task_path(task), class: "btn btn-secondary" %>
                        <%= button_to "\u524a\u9664", task_path(task), method: :delete, class: "btn btn-danger", form: { data: { turbo_confirm: "\u524a\u9664\u3057\u3066\u3088\u308d\u3057\u3044\u3067\u3059\u304b\uff1f" } } %>
                      </div>
                    </td>
                  </tr>
                <% end %>
              </tbody>
            </table>
          <% else %>
            <div class="card" style="text-align:center; color:#6b7280;">
              <p><%= params[:q].present? ? "\u691c\u7d22\u7d50\u679c\u304c\u898b\u3064\u304b\u308a\u307e\u305b\u3093\u3067\u3057\u305f" : "\u30bf\u30b9\u30af\u304c\u307e\u3060\u3042\u308a\u307e\u305b\u3093\u3002\u300c\u65b0\u898f\u4f5c\u6210\u300d\u304b\u3089\u8ffd\u52a0\u3057\u307e\u3057\u3087\u3046\uff01" %></p>
            </div>
          <% end %>
        ERB

        File.write(vuln_view_path.join("tasks/index.html.erb"), template)
        ActionController::Base.prepend_view_path(vuln_view_path.to_s)
      end
    end
  end
end
