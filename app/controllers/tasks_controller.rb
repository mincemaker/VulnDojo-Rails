# frozen_string_literal: true

require "csv"

class TasksController < ApplicationController
  before_action :set_task, only: %i[show edit update destroy download_attachment]

  # GET /tasks
  def index
    @tasks = current_user.tasks.order(created_at: :desc)
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
      safe_redirect_to params[:return_to], fallback: @task
      flash[:notice] = "タスクを作成しました。"
    else
      render :new, status: :unprocessable_entity
    end
  end

  # PATCH/PUT /tasks/1
  def update
    if @task.update(task_params)
      safe_redirect_to params[:return_to], fallback: @task
      flash[:notice] = "タスクを更新しました。"
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

  private

  # 所有者スコープ: IDOR 防止
  def set_task
    @task = current_user.tasks.find(params[:id])
  end

  # Strong Parameters: 許可リスト方式
  def task_params
    params.require(:task).permit(:title, :description, :completed, :due_date, :url, :secret_note, :attachment)
  end
end
