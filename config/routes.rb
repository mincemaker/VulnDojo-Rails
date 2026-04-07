Rails.application.routes.draw do
  # 認証
  get    "login",  to: "sessions#new",     as: :login
  post   "login",  to: "sessions#create"
  delete "logout", to: "sessions#destroy", as: :logout
  get    "signup", to: "users#new",        as: :signup
  post   "signup", to: "users#create"

  # タスク
  resources :tasks do
    member do
      get :download_attachment
    end
    collection do
      get :export
    end
  end

  # 脆弱性ダッシュボード
  get "vulnerabilities", to: "vulnerabilities#dashboard", as: :vulnerabilities_dashboard

  # ヘルスチェック
  get "up" => "rails/health#show", as: :rails_health_check

  root "tasks#index"
end
