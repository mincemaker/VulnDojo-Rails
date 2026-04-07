# frozen_string_literal: true

module Vulnerabilities
  module Challenges
    # チャレンジ14: Command Injection
    # CSVエクスポートのファイル名生成にシェルコマンドを使用し、
    # ユーザ入力がシェルに渡る脆弱性を注入する
    class CommandInjection < Base
      metadata do
        name        "Command Injection via filename sanitization"
        category    :injection
        difficulty  :hard
        description "CSVエクスポートのファイル名サニタイズ処理にシェルが使われており、コマンドインジェクションが可能です。"
        hint        "CSVエクスポートの name パラメータを確認してください"
        hint        "name=$(whoami) を試してみましょう — ファイル名にコマンド実行結果が含まれます"
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

            # 脆弱性: ファイル名の特殊文字をシェル経由でサニタイズしようとしている
            # tr で英数字以外を除去しているつもりが、$(whoami) 等のコマンド置換が先に展開される
            name = params[:name] || "tasks"
            safe_name = `echo #{name} | tr -cd '[:alnum:]_-'`.strip
            filename = "#{safe_name}_#{Date.current.strftime('%Y%m%d')}.csv"

            send_data csv_data,
                      filename: filename,
                      type: "text/csv; charset=utf-8"
          end
        end
        prepend_to TasksController, vuln_module
      end
    end
  end
end
