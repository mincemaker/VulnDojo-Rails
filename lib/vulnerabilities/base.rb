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
    # 既に同じ slug のモジュールが prepend されている場合はスキップする
    def prepend_to(klass, mod)
      slug = self.class.slug
      # 既にこのチャレンジのモジュールが適用されているか確認
      exists = klass.ancestors.any? do |ancestor|
        ancestor.instance_variable_get(:@vuln_slug) == slug
      end
      return if exists

      mod.instance_variable_set(:@vuln_slug, slug)
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
    def add_routes(&block)
      registry = Registry.instance
      slug = self.class.slug
      return if registry.route_applied?(slug)

      routes = Rails.application.routes
      return unless routes

      routes.prepend(&block)  # clear! のたびに再評価されるよう登録
      routes.disable_clear_and_finalize = true
      begin
        routes.draw(&block)
      rescue ArgumentError => e
        # ルート名重複は既に定義済みとして無視
        raise e unless e.message.include?("Invalid route name, already in use")
      end
      registry.mark_route_applied(slug)
    ensure
      routes&.respond_to?(:disable_clear_and_finalize=) && routes.disable_clear_and_finalize = false
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
