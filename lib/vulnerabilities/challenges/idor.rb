# frozen_string_literal: true

module Vulnerabilities
  module Challenges
    # チャレンジ5: IDOR (Insecure Direct Object Reference)
    # set_task を Task.find(params[:id]) に差し替え、他ユーザのタスクにアクセス可能にする
    class Idor < Base
      metadata do
        name        "IDOR — Insecure Direct Object Reference"
        category    :authorization
        difficulty  :easy
        description "タスクのアクセス制御が所有者スコープではなく、他ユーザのタスクを閲覧・編集・削除できます。"
        hint        "URLのタスクIDを変えて他人のタスクにアクセスしてみましょう"
        hint        "set_task が current_user.tasks.find ではなく Task.find になっています"
        cwe         "CWE-639"
        reference   "https://guides.rubyonrails.org/security.html#unauthorized-viewing"
        slot        "TasksController#set_task"
      end

      def apply!
        vuln_module = Module.new do
          private

          def set_task
            @task = Task.find(params[:id])  # 所有者スコープなし — IDOR 脆弱性
          end
        end
        prepend_to TasksController, vuln_module
      end
    end
  end
end
