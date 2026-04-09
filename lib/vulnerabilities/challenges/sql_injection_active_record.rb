# frozen_string_literal: true

module Vulnerabilities
  module Challenges
    # チャレンジ15: SQL Injection via ActiveRecord from() with CTE bypass
    # Rails 7.1+ の with() CTE を使ったタスクビュー機能で、
    # from() にユーザー入力が直接渡されることで SQL インジェクションが可能になる
    class SqlInjectionActiveRecord < Base
      metadata do
        name        "SQL Injection via ActiveRecord from() with CTE bypass"
        category    :injection
        difficulty  :hard
        description "タスク一覧のビュー切り替え機能に SQL インジェクションがあります。view_type パラメータを操作すると他ユーザーのタスクを閲覧できます。"
        hint        "view_type パラメータに todo_tasks 以外の値を渡してみましょう"
        hint        "ActiveRecord の from() は引数を SQL 断片として直接展開します"
        hint        "with() で作った CTE スコープはバイパスできます"
        cwe         "CWE-89"
        reference   "https://rails-sqli.org/#from"
      end

      def apply!
        vuln_module = Module.new do
          # set_view_type を上書き: 不正な view_type もそのまま通す（ホワイトリスト検証なし）
          def set_view_type
            @view_type = params[:view_type].presence || "todo_tasks"
          end

          # set_task_scope を上書き: from() に @view_type を直接渡す（SQL インジェクション）
          # 開発者の意図: view_type で CTE 名を切り替えてフィルタリング
          # 脆弱性: from() に view_type を直接渡しているため、任意の SQL 断片が注入できる
          #   例) view_type=tasks → WITH 句を無視して tasks テーブル全体を参照
          def set_task_scope
            base = current_user.tasks.select(
              :id, :title, :user_id, :completed, :due_date, :updated_at, :created_at
            )
            @tasks = Task.with(
              todo_tasks: base.where(completed: false),
              done_tasks: base.where(completed: true)
            ).from(@view_type).select("*")
          rescue ActiveRecord::StatementInvalid
            @tasks = current_user.tasks
          end
        end
        prepend_to TasksController, vuln_module
      end
    end
  end
end
