# frozen_string_literal: true

class SessionsController < ApplicationController
  skip_before_action :require_login, only: %i[new create]

  def new
  end

  def create
    # authenticate_by はユーザー不在でもダミー bcrypt を実行し定数時間を保証する（CWE-208 対策）
    user = User.authenticate_by(email: params[:email]&.downcase, password: params[:password])
    if user
      reset_session
      session[:user_id] = user.id
      redirect_to tasks_path, notice: "ログインしました。"
    else
      flash.now[:alert] = "メールアドレスまたはパスワードが正しくありません。"
      render :new, status: :unprocessable_entity
    end
  end

  def destroy
    reset_session
    redirect_to login_path, notice: "ログアウトしました。"
  end
end
