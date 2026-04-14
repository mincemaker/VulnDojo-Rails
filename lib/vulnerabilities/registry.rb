# frozen_string_literal: true

module Vulnerabilities
  # チャレンジの登録・有効化を管理するレジストリ
  class Registry
    include Singleton

    def initialize
      @challenges = {}   # slug => klass
      @active = Set.new  # 有効な slug の集合
      @conflict_log = [] # [{winner:, losers:, slot:}, ...]
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

    def conflict_log
      @conflict_log.dup
    end

    # --- 有効なチャレンジを適用 ---

    def apply_all!
      # 前回起動時に inject されたビューファイルをクリア
      # (古いファイルが prepend_view_path で意図せず優先されるのを防ぐ)
      FileUtils.rm_f(Dir[Rails.root.join("lib/vulnerabilities/views/**/*.erb")])

      resolve_conflicts!
      active_challenges.each do |klass|
        $stdout.puts "[Vuln] Applying challenge: #{klass.slug}"
        klass.new.apply!
      end

      vuln_view_path = Rails.root.join("lib/vulnerabilities/views").to_s
      if Dir.exist?(vuln_view_path) && Dir.glob("#{vuln_view_path}/**/*.erb").any?
        [ActionController::Base, *ActionController::Base.descendants].each do |ctrl|
          next unless ctrl.respond_to?(:view_paths)
          next if ctrl.view_paths.map(&:to_s).include?(vuln_view_path)
          ctrl.prepend_view_path(vuln_view_path)
        end
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

    private

    # claim! で各チャレンジの占有 slot を収集し、
    # 同 slot を複数チャレンジが競合していたらランダムで1つを残す。
    def resolve_conflicts!
      @conflict_log = []

      # slot => [slug, ...] マップを構築
      slot_map = Hash.new { |h, k| h[k] = [] }
      @active.each do |slug|
        klass = @challenges[slug]
        next unless klass
        klass.new.claim!.each { |slot| slot_map[slot] << slug }
      end

      # 競合する slot ごとにランダムで winner を決定
      losers = Set.new
      slot_map.each do |slot, slugs|
        next if slugs.size <= 1
        winner = slugs.sample
        defeated = slugs - [winner]
        defeated.each { |s| losers.add(s) }
        @conflict_log << { slot: slot, winner: winner, losers: defeated }
        $stdout.puts "[Vuln] Conflict on #{slot}: #{winner} wins over #{defeated.join(', ')}"
      end

      losers.each { |s| @active.delete(s) }
    end
  end
end
