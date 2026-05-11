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
        slot        "view:tasks/_task_color.html.erb"
      end

      def apply!
        inject_view "tasks/_task_color.html.erb", <<~'ERB'
          <% if task.color.present? %>
            <div class="detail-row" id="task-color-indicator" style="border-left: 4px solid <%= task.color %>; padding-left: 8px;">
              <div class="label">ラベルカラー</div>
              <div>
                <% if task.color.match?(/\A#[0-9a-fA-F]{3,6}\z/) %>
                  <span style="display:inline-block; width:16px; height:16px; background-color:<%= task.color %>; border:1px solid #ccc; border-radius:3px; vertical-align:middle;"></span>
                <% end %>
                <%= task.color %>
              </div>
            </div>
          <% end %>
        ERB
      end
    end
  end
end
