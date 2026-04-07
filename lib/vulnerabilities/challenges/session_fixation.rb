# frozen_string_literal: true

module Vulnerabilities
  module Challenges
    # チャレンジ6: Session Fixation
    # ログイン時の reset_session を削除し、セッション固定化攻撃を可能にする
    class SessionFixation < Base
      metadata do
        name        "Session Fixation — reset_session 無効化"
        category    :session
        difficulty  :medium
        description "ログイン時に reset_session が呼ばれないため、攻撃者が事前に取得したセッションIDを被害者に踏ませることでセッション固定化攻撃が成立します。"
        hint        "ログイン前のセッションID（_session_id）を取得し、そのIDで被害者をログインさせてみましょう"
        hint        "reset_session がないとサーバー側のセッションレコードにuser_idが書き込まれ、攻撃者のIDが認証済みになります"
        cwe         "CWE-384"
        reference   "https://guides.rubyonrails.org/security.html#session-fixation"
      end

      def apply!
        # SessionsController#create を上書きし、reset_session をスキップ
        vuln_module = Module.new do
          def create
            user = User.find_by(email: params[:email]&.downcase)
            if user&.authenticate(params[:password])
              # reset_session がない — Session Fixation 脆弱性
              session[:user_id] = user.id
              redirect_to tasks_path, notice: "ログインしました。"
            else
              flash.now[:alert] = "メールアドレスまたはパスワードが正しくありません。"
              render :new, status: :unprocessable_entity
            end
          end
        end
        prepend_to SessionsController, vuln_module
      end
    end
  end
end
