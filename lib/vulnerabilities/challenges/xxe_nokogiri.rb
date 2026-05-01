# frozen_string_literal: true

module Vulnerabilities
  module Challenges
    # チャレンジ: XXE via Nokogiri (CWE-611)
    # XMLインポート機能で Nokogiri::XML に config.noent を設定し、
    # 外部エンティティ展開を有効にする脆弱性
    class XxeNokogiri < Base
      metadata do
        name        "XXE via Nokogiri XML import"
        category    :injection
        difficulty  :hard
        description "XMLインポート機能が外部エンティティ展開を有効にしており、XXE攻撃でローカルファイルを読み取られる脆弱性があります。"
        hint        "タスクのXMLインポート機能を確認してください"
        hint        "Nokogiri::XML の noent オプションが設定されていないか確認しましょう"
        hint        "file:///etc/passwd を読み取る外部エンティティを試してみましょう"
        cwe         "CWE-611"
        reference   "https://guides.rubyonrails.org/security.html#xml-external-entities"
        slot        "TasksController#import_xml"
      end

      def apply!
        vuln_module = Module.new do
          def import_xml
            unless params[:xml_file].present?
              flash.now[:alert] = "XMLファイルを選択してください。"
              return render :import_xml_form, status: :unprocessable_entity
            end

            xml_content = params[:xml_file].read

            # 脆弱性: config.noent で外部エンティティ展開が有効になる
            doc = Nokogiri::XML(xml_content) do |config|
              config.noent
            end

            if doc.errors.any?
              flash.now[:alert] = "XMLの解析に失敗しました: #{doc.errors.first.message}"
              return render :import_xml_form, status: :unprocessable_entity
            end

            imported = 0
            errors = []

            doc.css("tasks task").each do |task_node|
              title = task_node.at_css("title")&.text&.strip
              description = task_node.at_css("description")&.text&.strip
              url = task_node.at_css("url")&.text&.strip

              if title.blank?
                errors << "タイトルが空のタスクをスキップしました"
                next
              end

              task = current_user.tasks.new(
                title: title,
                description: description,
                url: url.presence
              )

              if task.save
                imported += 1
              else
                errors.concat(task.errors.full_messages)
              end
            end

            if imported > 0
              flash[:notice] = "#{imported}件のタスクをインポートしました。"
            end

            if errors.any?
              flash[:alert] = "エラー: #{errors.join(", ")}"
            end

            redirect_to tasks_path
          end
        end
        prepend_to TasksController, vuln_module
      end
    end
  end
end
