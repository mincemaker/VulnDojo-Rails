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
        vuln_view_path = Rails.root.join("lib/vulnerabilities/views")
        FileUtils.mkdir_p(vuln_view_path.join("tasks"))

        # 脆弱な partial のみ注入: title を html_safe でエスケープなし表示
        template = <<~'ERB'
          <div class="detail-row">
            <div class="label">タイトル</div>
            <div><%= @task.title.html_safe %></div>
          </div>
        ERB

        File.write(vuln_view_path.join("tasks/_task_title.html.erb"), template)
        ActionController::Base.prepend_view_path(vuln_view_path.to_s)
      end
    end
  end
end
