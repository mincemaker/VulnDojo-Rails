# frozen_string_literal: true

module Vulnerabilities
  # チャレンジの登録・有効化を管理するレジストリ
  class Registry
    include Singleton

    def initialize
      @challenges = {}  # slug => klass
      @active = Set.new # 有効な slug の集合
    end

    # --- 登録 ---

    def register(klass)
      @challenges[klass.slug] = klass
    end

    def all_challenges
      @challenges.dup
    end

    # --- 有効化・無効化 ---

    def enable(slug)
      raise "Unknown challenge: #{slug}" unless @challenges.key?(slug)
      @active.add(slug)
    end

    def disable(slug)
      @active.delete(slug)
    end

    def enabled?(slug)
      @active.include?(slug)
    end

    def active_challenges
      @active.map { |slug| @challenges[slug] }.compact
    end

    def active_slugs
      @active.to_a
    end

    # --- 有効なチャレンジを適用 ---

    def apply_all!
      active_challenges.each do |klass|
        Rails.logger.info "[Vuln] Applying challenge: #{klass.slug}"
        klass.new.apply!
      end
    end

    # --- 環境変数 or 設定ファイルから初期化 ---

    def load_from_env!
      # VULN_CHALLENGES=xss_raw,sql_injection の形式
      # VULN_CHALLENGES=all で全チャレンジを有効化
      raw = ENV.fetch("VULN_CHALLENGES", "").strip
      if raw == "all"
        @challenges.keys.each { |s| enable(s) }
      else
        raw.split(",").map(&:strip).reject(&:empty?).each { |s| enable(s) }
      end
    end
  end
end
