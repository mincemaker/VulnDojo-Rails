# frozen_string_literal: true

require "test_helper"

# conflict 検出・解決機構の単体テスト
# xss_raw と同じ slot を持つダミーチャレンジを Registry に直接登録して検証する
class ConflictResolutionTest < ActiveSupport::TestCase
  CONFLICTING_SLUG = "xss_raw_v2_test_only"

  setup do
    @registry = Vulnerabilities::Registry.instance
    @original_active     = @registry.instance_variable_get(:@active).dup
    @original_challenges = @registry.instance_variable_get(:@challenges).dup
    @registry.instance_variable_set(:@active, Set.new)
    @registry.instance_variable_set(:@conflict_log, [])

    # xss_raw と同じ slot を狙うダミーチャレンジを登録
    dummy = Class.new(Vulnerabilities::Base) do
      define_singleton_method(:slug) { "xss_raw_v2_test_only" }
      def apply!
        inject_view "tasks/_task_title.html.erb", "<div>dummy</div>"
      end
    end
    @registry.instance_variable_get(:@challenges)[CONFLICTING_SLUG] = dummy

    @registry.enable("xss_raw")
    @registry.enable(CONFLICTING_SLUG)
  end

  teardown do
    @registry.instance_variable_set(:@active, @original_active)
    @registry.instance_variable_set(:@challenges, @original_challenges)
    @registry.instance_variable_set(:@conflict_log, [])
  end

  test "同じ slot を持つチャレンジの conflict が検出される" do
    @registry.send(:resolve_conflicts!)

    assert_equal 1, @registry.conflict_log.size
    entry = @registry.conflict_log.first
    assert_equal "view:tasks/_task_title.html.erb", entry[:slot]
    assert_includes ["xss_raw", CONFLICTING_SLUG], entry[:winner]
    assert_equal 1, entry[:losers].size
  end

  test "conflict 解決後は一方だけが active に残る" do
    @registry.send(:resolve_conflicts!)

    assert_equal 1, @registry.active_slugs.size
    assert(
      @registry.active_slugs.include?("xss_raw") ||
      @registry.active_slugs.include?(CONFLICTING_SLUG)
    )
  end
end
