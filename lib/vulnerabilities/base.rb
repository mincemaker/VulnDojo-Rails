# frozen_string_literal: true

module Vulnerabilities
  # 脆弱性チャレンジの基底クラス
  # 各チャレンジは apply! で脆弱性を注入し、メタデータを定義する
  class Base
    class << self
      attr_reader :meta

      def metadata(&block)
        @meta ||= {}
        dsl = MetadataDSL.new(@meta)
        dsl.instance_eval(&block)
      end

      def slug
        name.demodulize.underscore
      end
    end

    # apply! を各サブクラスで実装する
    def apply!
      raise NotImplementedError, "#{self.class}#apply! を実装してください"
    end

    # metadata の slot 宣言に基づき占有する slot キーの一覧を返す。
    # apply! は呼ばないため副作用ゼロ。
    # 全チャレンジは metadata ブロックで slot を宣言する必要がある。
    def claim!
      self.class.meta&.dig(:slots) || []
    end

    private

    # コントローラに prepend でメソッドを差し込む
    def prepend_to(klass, mod)
      klass.prepend(mod)
    end

    # view パーシャルを lib/vulnerabilities/views/ 以下に書き込み、
    # prepend_view_path でアプリのビューより優先させる。
    def inject_view(relative_path, content)
      vuln_view_path = Rails.root.join("lib/vulnerabilities/views")
      FileUtils.mkdir_p(vuln_view_path.join(File.dirname(relative_path)))
      File.write(vuln_view_path.join(relative_path), content)
    end

    # 動的にルートを追加する
    # draw(&block) はデフォルトで clear! → eval → finalize! の順に動くため、
    # そのまま呼ぶと既存ルートが全消えになる。
    # routes.prepend でブロックを @prepend に登録しておくと、
    # ルート再ロード時の clear! でも再評価されて消えなくなる。
    # さらに disable_clear_and_finalize = true で draw を呼ぶことで
    # 即時評価しつつ既存ルートを保つ。
    def add_routes(&block)
      routes = Rails.application.routes
      routes.prepend(&block)  # clear! のたびに再評価されるよう登録
      routes.disable_clear_and_finalize = true
      routes.draw(&block)     # 現時点でも即時評価
    ensure
      routes.disable_clear_and_finalize = false
    end

    # 設定値を変更する
    def configure_app(&block)
      Rails.application.configure(&block)
    end

    # メタデータ定義用DSL
    class MetadataDSL
      def initialize(hash)
        @hash = hash
      end

      def name(val);        @hash[:name] = val; end
      def category(val);    @hash[:category] = val; end
      def difficulty(val);  @hash[:difficulty] = val; end
      def description(val); @hash[:description] = val; end
      def hint(val);        (@hash[:hints] ||= []) << val; end
      def cwe(val);         @hash[:cwe] = val; end
      def reference(val);   @hash[:reference] = val; end
      def slot(*vals);      (@hash[:slots] ||= []).concat(vals); end
    end
  end
end
