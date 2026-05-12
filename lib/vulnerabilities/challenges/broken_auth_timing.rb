# frozen_string_literal: true

module Vulnerabilities
  module Challenges
    class BrokenAuthTiming < Base
      metadata do
        name        "Timing Attack on Login (User Enumeration)"
        category    :authentication
        difficulty  :hard
        description "ユーザーが存在しない場合は bcrypt 比較をスキップして即 return するため、レスポンス時間の差でユーザー列挙が可能です。"
        hint        "存在するメールアドレスと存在しないメールアドレスで複数回ログインを試みてください。レスポンス時間に差はありますか？"
        hint        "bcrypt のハッシュ比較は計算コストが高い処理です。ユーザーが見つからないとき何が省略されているでしょうか"
        cwe         "CWE-208"
        reference   "https://owasp.org/www-community/attacks/Timing_attack"
        slot        "User.authenticate_by"
      end

      def apply!
        # テスト環境等でハッシュ計算が速すぎる場合、ネットワーク越しのタイミング攻撃が
        # 観測不能になるため、本チャレンジ有効時のみ BCrypt の計算コストを引き上げる
        ActiveModel::SecurePassword.min_cost = false
        BCrypt::Engine.cost = 10

        vuln_module = Module.new do
          def authenticate_by(attributes)
            passwords, identifiers = attributes.to_h.partition { |name, _|
              !has_attribute?(name) && has_attribute?("#{name}_digest")
            }.map(&:to_h)
            return if passwords.any? { |_, v| v.nil? || v.empty? }

            record = find_by(identifiers)
            record if record && passwords.all? { |name, value|
              record.public_send(:"authenticate_#{name}", value)
            }
          end
        end
        prepend_to User.singleton_class, vuln_module
      end
    end
  end
end
