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

    # apply! を dry-run して占有する slot キーの一覧を返す。
    # prepend_to / inject_view をシングルトンメソッドで一時差し替えし、
    # 実際の inject は行わずキーだけ記録する。
    def claim!
      slots = []
      define_singleton_method(:prepend_to) do |klass, mod|
        mod.instance_methods(false).each { |m| slots << "#{klass.name}##{m}" }
      end
      define_singleton_method(:inject_view) do |path, _content|
        slots << "view:#{path}"
      end
      apply!
      slots
    ensure
      singleton_class.remove_method(:prepend_to) rescue nil
      singleton_class.remove_method(:inject_view) rescue nil
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
      ActionController::Base.prepend_view_path(vuln_view_path.to_s)
    end

    # 動的にルートを追加する
    def add_routes(&block)
      Rails.application.routes.draw(&block)
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
    end
  end
end
