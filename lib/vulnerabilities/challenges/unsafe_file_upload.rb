# frozen_string_literal: true

module Vulnerabilities
  module Challenges
    # チャレンジ9: Unsafe File Upload
    # 添付ファイルのMIMEタイプ・サイズ検証を無効化する
    class UnsafeFileUpload < Base
      metadata do
        name        "Unsafe File Upload — MIME validation disabled"
        category    :upload
        difficulty  :medium
        description "添付ファイルのMIMEタイプ検証が無効化され、任意のファイルがアップロード可能です。"
        hint        "実行可能ファイル (.exe, .sh) をアップロードしてみましょう"
        hint        "MIMEタイプのホワイトリスト検証が無効になっています"
        cwe         "CWE-434"
        reference   "https://guides.rubyonrails.org/security.html#file-uploads"
      end

      def apply!
        # acceptable_attachment バリデーションを空のメソッドで上書き
        Task.class_eval do
          define_method(:acceptable_attachment) { }  # 検証なし — Unsafe Upload 脆弱性
        end
      end
    end
  end
end
