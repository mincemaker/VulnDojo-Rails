# frozen_string_literal: true

module Vulnerabilities
  module Challenges
    # チャレンジ: XSS (Reflected)
    # タスク一覧の検索キーワードをエスケープせずに反射させる
    class XssReflected < Base
      metadata do
        name        "Reflected XSS via search keyword"
        category    :xss
        difficulty  :medium
        description "タスク一覧の検索結果ラベルで検索キーワードがエスケープされずに出力されます。Reflected XSS が可能です。"
        hint        "タスク一覧で検索してみましょう"
        hint        "?q=<script>alert(1)</script> を URL に入れてみましょう"
        cwe         "CWE-79"
        reference   "https://guides.rubyonrails.org/security.html#cross-site-scripting-xss"
      end

      def apply!
        inject_view "tasks/_search_label.html.erb", <<~'ERB'
          <% if params[:q].present? %>
            <div style="margin-bottom:8px; color:#6b7280; font-size:0.9rem;">
              「<%== params[:q] %>」の検索結果
            </div>
          <% end %>
        ERB
      end
    end
  end
end
