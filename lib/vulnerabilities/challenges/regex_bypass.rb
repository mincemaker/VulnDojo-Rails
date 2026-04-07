# frozen_string_literal: true

module Vulnerabilities
  module Challenges
    # チャレンジ8: Regex Bypass
    # URLバリデーションを /^https?:\/\// に差し替え、
    # 改行を含む入力でバイパス可能にする
    class RegexBypass < Base
      metadata do
        name        "Regex Bypass — ^ vs \\A anchor"
        category    :validation
        difficulty  :medium
        description "URLバリデーションの正規表現が ^ を使っており、改行を含む入力でバイパスできます。"
        hint        "\\A と ^ の違いを確認してください"
        hint        "URLフィールドに\\njavascript:alert(1) のような値を入れてみましょう"
        cwe         "CWE-185"
        reference   "https://guides.rubyonrails.org/security.html#regular-expressions"
      end

      def apply!
        # Task モデルの url バリデーションを差し替える
        # \A -> ^ に変更 (行頭マッチになるため改行後の文字列が通過)
        Task.class_eval do
          # 既存のバリデーションを削除
          _validators[:url]&.reject! { |v| v.is_a?(ActiveModel::Validations::FormatValidator) }
          _validate_callbacks.each do |callback|
            if callback.filter.is_a?(ActiveModel::Validations::FormatValidator) &&
               callback.filter.attributes.include?(:url)
              _validate_callbacks.delete(callback)
            end
          end

          # ^ を使った脆弱なバリデーションを追加
          validates :url,
                    format: { with: /^https?:\/\/.+/m,  # ^ = 行頭マッチ (脆弱)
                              message: "は http:// または https:// で始まる必要があります",
                              multiline: true },
                    allow_blank: true
        end
      end
    end
  end
end
