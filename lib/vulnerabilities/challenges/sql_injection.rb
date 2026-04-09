# frozen_string_literal: true

module Vulnerabilities
  module Challenges
    # チャレンジ2: SQL Injection
    # 検索機能を追加し、文字列補間で脆弱なSQLを実行する
    class SqlInjection < Base
      metadata do
        name        "SQL Injection via search"
        category    :injection
        difficulty  :medium
        description "タスク検索機能に SQL インジェクションの脆弱性があります。"
        hint        "検索パラメータの処理方法を確認してください"
        hint        "' OR 1=1-- を検索ボックスに入れてみましょう"
        cwe         "CWE-89"
        reference   "https://guides.rubyonrails.org/security.html#sql-injection"
      end

      def apply!
        # apply_task_search のみ上書きして脆弱な検索を注入
        # set_view_type / set_task_scope はベースコントローラに委ねる
        vuln_module = Module.new do
          def apply_task_search
            # ↓ 脆弱性: 文字列補間による SQL インジェクション
            # Task.where に1つの文字列として渡すことで OR 1=1 がユーザースコープを越えられる
            @tasks = Task.where("user_id = #{current_user.id} AND title LIKE '%#{params[:q]}%'") if params[:q].present?
          end
        end
        prepend_to TasksController, vuln_module
      end
    end
  end
end
