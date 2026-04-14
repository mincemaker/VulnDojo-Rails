# frozen_string_literal: true

module Vulnerabilities
  module Challenges
    # チャレンジ3: CSRF 保護無効化
    # protect_from_forgery を無効化し、外部からの POST を許可
    class CsrfSkip < Base
      metadata do
        name        "CSRF protection disabled"
        category    :csrf
        difficulty  :easy
        description "CSRF 保護が無効化されています。外部サイトからの不正リクエストが可能です。"
        hint        "フォーム送信時のトークン検証が行われているか確認してください"
        hint        "curl で直接 POST してタスクが作成できるか試してみましょう"
        cwe         "CWE-352"
        reference   "https://guides.rubyonrails.org/security.html#cross-site-request-forgery-csrf"
        slot        "TasksController.forgery_protection"
      end

      def apply!
        # TasksController の CSRF 保護を無効化
        TasksController.skip_forgery_protection
      end
    end
  end
end
