# frozen_string_literal: true

module Vulnerabilities
  module Challenges
    # チャレンジ3: CSRF 保護無効化
    # トークン検証と HTTPS の SameSite 制限を外し、外部からの POST を許可
    class CsrfSkip < Base
      metadata do
        name        "CSRF protection disabled"
        category    :csrf
        difficulty  :easy
        description "CSRF 保護が無効化されています。外部サイトからの不正リクエストが可能です。"
        hint        "フォーム送信時のトークン検証が行われているか確認してください"
        hint        "HTTPS でログインし、別サイトのフォームから POST したときに Cookie が送られるか確認してください"
        cwe         "CWE-352"
        reference   "https://guides.rubyonrails.org/security.html#cross-site-request-forgery-csrf"
        slot        "TasksController.forgery_protection", "ApplicationController.csrf_session_cookie"
      end

      module CrossSiteSession
        private

        def allow_csrf_session_cookie
          # HTTP で Secure を指定するとセッションを保存できないため、再現は HTTPS に限定する。
          return unless request.ssl?

          request.session_options[:same_site] = :none
          request.session_options[:secure] = true
        end
      end

      def apply!
        # CSRF 教材のため、ログイン時から SameSite 制限を外し、タスクのトークン検証も無効化する。
        prepend_to(ApplicationController, CrossSiteSession)
        ApplicationController.prepend_before_action :allow_csrf_session_cookie
        TasksController.skip_forgery_protection
      end
    end
  end
end
