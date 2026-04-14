# frozen_string_literal: true

module Vulnerabilities
  module Challenges
    # チャレンジ: SQL Injection via ActiveRecord order()
    # ソート機能で Arel.sql() を使いユーザー入力を ORDER BY に直接渡している。
    # apply_task_search を上書きするため sql_injection チャレンジと slot が競合する。
    class SqlInjectionOrder < Base
      metadata do
        name        "SQL Injection via ActiveRecord order()"
        category    :injection
        difficulty  :medium
        description "タスクのソート機能に SQL インジェクションがあります。sort パラメータが Arel.sql() 経由で ORDER BY 句に直接渡されます。"
        hint        "sort パラメータに列名以外の値を渡してみましょう"
        hint        "Arel.sql() は Rails の UnknownAttributeReference 保護をバイパスします"
        hint        "sort=(CASE WHEN 1=1 THEN title ELSE created_at END) でブラインド注入が可能です"
        cwe         "CWE-89"
        reference   "https://rails-sqli.org/#order"
        slot        "TasksController#apply_task_search"
      end

      def apply!
        # apply_task_search を上書き。
        # sql_injection チャレンジも同じメソッドを上書きするため、
        # 両方を同時に有効化すると TasksController#apply_task_search スロットで conflict が発生する。
        vuln_module = Module.new do
          def apply_task_search
            @tasks = @tasks.where("title LIKE ?", "%#{params[:q]}%") if params[:q].present?
            # ↓ 脆弱性: Arel.sql() で Rails の UnknownAttributeReference 保護をバイパスし、
            #   ユーザー入力をそのまま ORDER BY 句に渡している。
            #   開発者の意図: 列名を文字列で受け取って動的ソートを実現しようとした。
            #   実際の影響: 任意の SQL 式 (CASE WHEN, サブクエリなど) が注入可能。
            @tasks = @tasks.order(Arel.sql(params[:sort])) if params[:sort].present?
          end
        end
        prepend_to TasksController, vuln_module
      end
    end
  end
end
