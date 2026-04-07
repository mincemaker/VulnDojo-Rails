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

    private

    # コントローラに prepend でメソッドを差し込む
    def prepend_to(klass, mod)
      klass.prepend(mod)
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
