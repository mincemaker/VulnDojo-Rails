# frozen_string_literal: true

class SessionsController < ApplicationController
  skip_before_action :require_login, only: %i[new create]

  def new
  end

  def create
    # find_by → ユーザー不在時は bcrypt をスキップして即 return（CWE-208）
    user = User.find_by(email: params[:email]&.downcase)
    unless user
      flash.now[:alert] = "認証に失敗しました。"
      return render :new, status: :unprocessable_entity
    end
    if user.authenticate(params[:password])
      # reset_session なし — Session Fixation 脆弱性（baked-in の session_fixation と競合回避のため）
      session[:user_id] = user.id
      redirect_to tasks_path
    else
      flash.now[:alert] = "認証に失敗しました。"
      render :new, status: :unprocessable_entity
    end
  end

  def destroy
    reset_session
    redirect_to login_path, notice: "ログアウトしました。"
  end
end
