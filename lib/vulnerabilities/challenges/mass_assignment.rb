# frozen_string_literal: true

module Vulnerabilities
  module Challenges
    # チャレンジ7: Mass Assignment
    # task_params で permit! を使い、user_id を含む全属性を許可する
    class MassAssignment < Base
      metadata do
        name        "Mass Assignment via permit!"
        category    :authorization
        difficulty  :medium
        description "Strong Parameters が無効化され、user_id 等の保護属性も変更可能です。"
        hint        "タスク更新時に user_id パラメータを送信してみましょう"
        hint        "permit! は全パラメータを許可します"
        cwe         "CWE-915"
        reference   "https://guides.rubyonrails.org/security.html#mass-assignment"
      end

      def apply!
        vuln_module = Module.new do
          private

          def task_params
            params.require(:task).permit!  # 全属性許可 — Mass Assignment 脆弱性
          end
        end
        prepend_to TasksController, vuln_module
      end
    end
  end
end
