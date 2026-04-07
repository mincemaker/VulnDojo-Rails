# frozen_string_literal: true

module Vulnerabilities
  module Challenges
    # チャレンジ14: Command Injection
    # CSVエクスポートのファイル名生成にシェルコマンドを使用し、
    # ユーザ入力がシェルに渡る脆弱性を注入する
    class CommandInjection < Base
      metadata do
        name        "Command Injection via CSV export"
        category    :injection
        difficulty  :hard
        description "CSVエクスポートのファイル名生成にシェルコマンドインジェクションの脆弱性があります。"
        hint        "CSVエクスポートの name パラメータを確認してください"
        hint        "name=`id` や name=$(whoami) を試してみましょう"
        cwe         "CWE-78"
        reference   "https://guides.rubyonrails.org/security.html#command-line-injection"
      end

      def apply!
        vuln_module = Module.new do
          def export
            tasks = current_user.tasks.order(created_at: :desc)

            csv_data = CSV.generate(headers: true) do |csv|
              csv << %w[タイトル 説明 状態 期限 URL]
              tasks.each do |task|
                csv << [
                  task.title,
                  task.description,
                  task.completed? ? "完了" : "未完了",
                  task.due_date&.strftime("%Y-%m-%d"),
                  task.url
                ]
              end
            end

            # 脆弱性: ユーザ入力をシェルコマンドでファイル名生成に使用
            name = params[:name] || "tasks"
            filename = `echo #{name}_#{Date.current.strftime('%Y%m%d')}.csv`

            send_data csv_data,
                      filename: filename.strip,
                      type: "text/csv; charset=utf-8"
          end
        end
        prepend_to TasksController, vuln_module
      end
    end
  end
end
