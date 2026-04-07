# frozen_string_literal: true

module Vulnerabilities
  module Challenges
    # チャレンジ12: HTTP Security Headers Removal
    # X-Frame-Options, X-Content-Type-Options 等のセキュリティヘッダを削除する
    class HeaderRemoval < Base
      metadata do
        name        "HTTP Security Headers Removed"
        category    :headers
        difficulty  :easy
        description "セキュリティヘッダが削除され、ClickjackingやMIME Sniffing攻撃に脆弱です。"
        hint        "レスポンスヘッダに X-Frame-Options があるか確認してください"
        hint        "X-Content-Type-Options: nosniff が欠落しています"
        cwe         "CWE-693"
        reference   "https://guides.rubyonrails.org/security.html#default-headers"
      end

      def apply!
        # レスポンス送信後にセキュリティヘッダを削除する
        ApplicationController.after_action do
          response.headers.delete("X-Frame-Options")
          response.headers.delete("X-Content-Type-Options")
          response.headers.delete("X-Permitted-Cross-Domain-Policies")
          response.headers.delete("Referrer-Policy")
        end
      end
    end
  end
end
