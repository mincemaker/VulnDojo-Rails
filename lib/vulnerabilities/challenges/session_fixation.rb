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
        description "ログイン時にセッションIDが再生成されません。セッション固定化攻撃が可能です。"
        hint        "ログイン前後でセッションCookieの値が変わるか確認してください"
        hint        "reset_session が呼ばれていないため、攻撃者が事前にセットしたIDがそのまま使われます"
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
