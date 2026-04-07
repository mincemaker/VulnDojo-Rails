# frozen_string_literal: true

module Vulnerabilities
  module Challenges
    # チャレンジ1: XSS (Stored)
    # TasksController#show のタイトル表示を html_safe に差し替える
    class XssRaw < Base
      metadata do
        name        "Stored XSS via html_safe"
        category    :xss
        difficulty  :easy
        description "タスクのタイトルがエスケープされずに表示されています。Stored XSS が可能です。"
        hint        "タスク詳細ページのタイトル表示を確認してください"
        hint        "<script>alert('XSS')</script> をタイトルに入れてみましょう"
        cwe         "CWE-79"
        reference   "https://guides.rubyonrails.org/security.html#cross-site-scripting-xss"
      end

      def apply!
        # show テンプレートを脆弱版に差し替える。
        # テンプレート内で直接 html_safe を呼ぶことで XSS を再現。
        inject_vulnerable_show_template!
      end

      private

      def inject_vulnerable_show_template!
        vuln_view_path = Rails.root.join("lib/vulnerabilities/views")
        FileUtils.mkdir_p(vuln_view_path.join("tasks"))

        # 脆弱なテンプレート: title を html_safe でエスケープなし表示
        template = <<~'ERB'
          <div class="card">
            <div class="detail-row">
              <div class="label">タイトル</div>
              <div><%= @task.title.html_safe %></div>
            </div>

            <div class="detail-row">
              <div class="label">説明</div>
              <div><%= @task.description.present? ? @task.description : "—" %></div>
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
