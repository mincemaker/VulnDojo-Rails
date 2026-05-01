# frozen_string_literal: true

require "csv"
require "nokogiri"

class TasksController < ApplicationController
  before_action :set_task, only: %i[show edit update destroy download_attachment]

  ALLOWED_VIEW_TYPES = %w[todo_tasks done_tasks].freeze

  # GET /tasks
  def index
    set_view_type
    set_task_scope
    apply_task_search
    @tasks = @tasks.order(created_at: :desc)
  end

  # GET /tasks/1
  def show
  end

  # GET /tasks/new
  def new
    @task = current_user.tasks.build
  end

  # GET /tasks/1/edit
  def edit
  end

  # POST /tasks
  def create
    @task = current_user.tasks.build(task_params)

    if @task.save
      flash[:notice] = "タスクを作成しました。"
      safe_redirect_to params[:return_to], fallback: @task
    else
      render :new, status: :unprocessable_entity
    end
  end

  # PATCH/PUT /tasks/1
  def update
    if @task.update(task_params)
      flash[:notice] = "タスクを更新しました。"
      safe_redirect_to params[:return_to], fallback: @task
    else
      render :edit, status: :unprocessable_entity
    end
  end

  # DELETE /tasks/1
  def destroy
    @task.destroy!
    redirect_to tasks_url, notice: "タスクを削除しました。", status: :see_other
  end

  # GET /tasks/export.csv
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

    send_data csv_data,
              filename: "tasks_#{Date.current.strftime('%Y%m%d')}.csv",
              type: "text/csv; charset=utf-8"
  end

  # GET /tasks/:id/attachment
  def download_attachment
    if @task.attachment.attached?
      redirect_to rails_blob_path(@task.attachment, disposition: "attachment"), allow_other_host: false
    else
      redirect_to @task, alert: "添付ファイルがありません。"
    end
  end

  # GET /tasks/import_xml
  def import_xml_form
  end

  # POST /tasks/import_xml
  def import_xml
    unless params[:xml_file].present?
      flash.now[:alert] = "XMLファイルを選択してください。"
      return render :import_xml_form, status: :unprocessable_entity
    end

    xml_content = params[:xml_file].read
    doc = Nokogiri::XML(xml_content)

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
      flash.now[:alert] = "エラー: #{errors.join(", ")}"
    end

    redirect_to tasks_path
  end

  # GET /tasks/download_xml_template
  def download_xml_template
    template = <<~XML
      <?xml version="1.0" encoding="UTF-8"?>
      <tasks>
        <task>
          <title>タスクタイトル</title>
          <description>タスクの説明</description>
          <url>https://example.com</url>
        </task>
      </tasks>
    XML

    send_data template,
              filename: "task_import_template.xml",
              type: "application/xml; charset=utf-8"
  end

  private

  def set_view_type
    @view_type = ALLOWED_VIEW_TYPES.include?(params[:view_type]) ? params[:view_type] : nil
  end

  def set_task_scope
    @tasks = case @view_type
             when "todo_tasks" then current_user.tasks.where(completed: false)
             when "done_tasks" then current_user.tasks.where(completed: true)
             else current_user.tasks
             end
  end

  def apply_task_search
    @tasks = @tasks.where("title LIKE ?", "%#{params[:q]}%") if params[:q].present?
  end

  # 所有者スコープ: IDOR 防止
  def set_task
    @task = current_user.tasks.find(params[:id])
  end

  # Strong Parameters: 許可リスト方式
  def task_params
    params.require(:task).permit(:title, :description, :completed, :due_date, :url, :secret_note, :attachment, :color)
  end
end
