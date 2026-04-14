# frozen_string_literal: true

module Vulnerabilities
  module Challenges
    # チャレンジ4: Open Redirect
    # safe_redirect_to のバリデーションを無効化し、
    # params[:return_to] をそのまま redirect_to に渡す
    class OpenRedirect < Base
      metadata do
        name        "Open Redirect via return_to"
        category    :redirect
        difficulty  :easy
        description "リダイレクト先のバリデーションが無効化されています。外部サイトへの誘導が可能です。"
        hint        "タスク作成後のリダイレクト先を確認してください"
        hint        "return_to パラメータに外部URLを指定してみましょう"
        cwe         "CWE-601"
        reference   "https://guides.rubyonrails.org/security.html#redirection"
        slot        "ApplicationController#safe_redirect_to"
      end

      def apply!
        # safe_redirect_to を上書きして、バリデーションなしで redirect_to する
        vuln_module = Module.new do
          private

          def safe_redirect_to(url, fallback:)
            if url.present?
              redirect_to url, allow_other_host: true  # 検証なし — Open Redirect 脆弱性
            else
              redirect_to fallback
            end
          end
        end
        prepend_to ApplicationController, vuln_module
      end
    end
  end
end
