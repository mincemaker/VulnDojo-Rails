# frozen_string_literal: true

module Vulnerabilities
  module Challenges
    # チャレンジ11: CSS Injection
    # タスクのラベルカラーを style 属性にバリデーションなしで埋め込み、CSSインジェクションを可能にする
    class CssInjection < Base
      metadata do
        name        "CSS Injection via label color"
        category    :xss
        difficulty  :medium
        description "タスクのラベルカラーがバリデーションされずに style 属性に直接埋め込まれ、CSSインジェクションが可能です。"
        hint        "タスクのラベルカラーが style 属性として使われています"
        hint        "カラーに 'red; background:blue' を入れてページの見た目が変わるか確認しましょう"
        cwe         "CWE-79"
        reference   "https://guides.rubyonrails.org/security.html#css-injection"
      end

      def apply!
        vuln_view_path = Rails.root.join("lib/vulnerabilities/views")
        FileUtils.mkdir_p(vuln_view_path.join("tasks"))

        # 脆弱な partial のみ注入: color をバリデーションなしで style 属性に埋め込む
        template = <<~'ERB'
          <% if @task.color.present? %>
            <div class="detail-row" id="task-color-indicator" style="border-left: 4px solid <%= @task.color %>; padding-left: 8px;">
              <div class="label">ラベルカラー</div>
              <div><%= @task.color %></div>
            </div>
          <% end %>
        ERB

        File.write(vuln_view_path.join("tasks/_task_color.html.erb"), template)
        ActionController::Base.prepend_view_path(vuln_view_path.to_s)
      end
    end
  end
end
