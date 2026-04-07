# frozen_string_literal: true

module Vulnerabilities
  module Challenges
    # チャレンジ11: CSS Injection
    # タスクの description を style 属性として出力し、CSSインジェクションを可能にする
    class CssInjection < Base
      metadata do
        name        "CSS Injection via style attribute"
        category    :xss
        difficulty  :medium
        description "タスクの説明が style 属性にそのまま埋め込まれ、CSSインジェクションが可能です。"
        hint        "タスク詳細ページの説明が style 属性として使われています"
        hint        "説明に 'background:red' を入れてページの見た目が変わるか確認しましょう"
        cwe         "CWE-79"
        reference   "https://guides.rubyonrails.org/security.html#css-injection"
      end

      def apply!
        inject_vulnerable_show_template!
      end

      private

      def inject_vulnerable_show_template!
        vuln_view_path = Rails.root.join("lib/vulnerabilities/views")
        FileUtils.mkdir_p(vuln_view_path.join("tasks"))

        # show テンプレート: description を style 属性に埋め込む
        template = <<~'ERB'
          <div class="card">
            <div class="detail-row">
              <div class="label">タイトル</div>
              <div><%= @task.title %></div>
            </div>

            <div class="detail-row">
              <div class="label">説明</div>
              <div id="task-description" style="<%= @task.description %>">
                <%= @task.description.present? ? @task.description : "—" %>
              </div>
            </div>

            <div class="detail-row">
              <div class="label">状態</div>
              <div>
                <% if @task.completed? %>
                  <span class="badge badge-done">✅ 完了</span>
                <% else %>
                  <span class="badge badge-todo">⏳ 未完了</span>
                <% end %>
              </div>
            </div>

            <div class="detail-row">
              <div class="label">期限</div>
              <div><%= @task.due_date&.strftime("%Y-%m-%d") || "—" %></div>
            </div>

            <div class="actions" style="margin-top: 20px;">
              <%= link_to "編集", edit_task_path(@task), class: "btn btn-primary" %>
              <%= link_to "一覧に戻る", tasks_path, class: "btn btn-secondary" %>
              <%= button_to "削除", task_path(@task), method: :delete, class: "btn btn-danger" %>
            </div>
          </div>
        ERB

        File.write(vuln_view_path.join("tasks/show.html.erb"), template)
        ActionController::Base.prepend_view_path(vuln_view_path.to_s)
      end
    end
  end
end
