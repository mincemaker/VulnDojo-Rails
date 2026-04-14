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
        slot        "view:tasks/_task_title.html.erb"
      end

      def apply!
        inject_view "tasks/_task_title.html.erb", <<~'ERB'
          <div class="detail-row">
            <div class="label">タイトル</div>
            <div><%= @task.title.html_safe %></div>
          </div>
        ERB
      end
    end
  end
end
