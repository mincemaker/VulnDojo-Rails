# frozen_string_literal: true

module Vulnerabilities
  module Challenges
    # チャレンジ10: Log Leakage
    # パラメータフィルタを全削除し、機密情報がログに平文で記録されるようにする
    class LogLeakage < Base
      metadata do
        name        "Log Leakage — parameter filter disabled"
        category    :logging
        difficulty  :easy
        description "パラメータフィルタが無効化され、パスワードやsecret_noteがログに平文で記録されます。"
        hint        "ログファイルにパスワードや機密情報が平文で記録されています"
        hint        "config.filter_parameters が空になっています"
        cwe         "CWE-532"
        reference   "https://guides.rubyonrails.org/security.html#logging"
      end

      def apply!
        # パラメータフィルタを全削除
        Rails.application.config.filter_parameters.clear
        Rails.application.env_config["action_dispatch.parameter_filter"] = []
      end
    end
  end
end
