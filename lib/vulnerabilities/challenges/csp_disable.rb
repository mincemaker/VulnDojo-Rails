# frozen_string_literal: true

module Vulnerabilities
  module Challenges
    # チャレンジ13: CSP Disable
    # Content Security Policy を無効化し、インラインスクリプト実行を可能にする
    class CspDisable < Base
      metadata do
        name        "Content Security Policy Disabled"
        category    :headers
        difficulty  :easy
        description "CSP が無効化され、インラインスクリプトや外部リソースの読み込みが可能です。"
        hint        "レスポンスヘッダに Content-Security-Policy があるか確認してください"
        hint        "CSP がない場合、XSSの影響が大きくなります"
        cwe         "CWE-693"
        reference   "https://guides.rubyonrails.org/security.html#content-security-policy"
      end

      def apply!
        # ApplicationController で CSP を空にオーバーライド
        ApplicationController.content_security_policy(false)
      end
    end
  end
end
