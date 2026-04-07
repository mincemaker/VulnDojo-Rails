# frozen_string_literal: true

class ApplicationController < ActionController::Base
  before_action :require_login
  helper_method :current_user, :logged_in?

  private

  def current_user
    @current_user ||= User.find_by(id: session[:user_id]) if session[:user_id]
  end

  def logged_in?
    current_user.present?
  end

  def require_login
    unless logged_in?
      redirect_to login_path, alert: "ログインしてください。"
    end
  end

  # 安全なリダイレクト: 内部パスのみ許可
  def safe_redirect_to(url, fallback:)
    if url.present? && url.start_with?("/") && !url.start_with?("//")
      redirect_to url
    else
      redirect_to fallback
    end
  end
end
