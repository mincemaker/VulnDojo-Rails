# frozen_string_literal: true

require "test_helper"

# routes.prepend に登録したブロックは Rails の clear! で再実行される。
# また開発モードでは Registry クラスが再ロードされ、Singleton インスタンスが
# リセットされることで apply_all! が複数回 add_routes を実行する。
# いずれのケースでも ArgumentError が発生しないことを検証する。
class AddRoutesIdempotencyTest < ActiveSupport::TestCase
  TEST_SLUG = "test_add_routes_idempotency"
  TEST_ROUTE_AS = :test_idempotency_route_unique

  setup do
    @registry = Vulnerabilities::Registry.instance
    @original_active     = @registry.instance_variable_get(:@active).dup
    @original_challenges = @registry.instance_variable_get(:@challenges).dup
    @original_applied    = @registry.instance_variable_get(:@applied_routes)&.dup || Set.new
    @original_prepend    = Rails.application.routes.instance_variable_get(:@prepend).dup

    @registry.instance_variable_set(:@active, Set.new)
    @registry.instance_variable_set(:@conflict_log, [])
    @registry.instance_variable_set(:@applied_routes, Set.new)

    dummy = Class.new(Vulnerabilities::Base) do
      define_singleton_method(:slug) { "test_add_routes_idempotency" }
      metadata { slot "route:test_add_routes_idempotency" }
      def apply!
        add_routes do
          post "/test_idempotency_route_unique", to: "tasks#index", as: :test_idempotency_route_unique
        end
      end
    end
    @registry.instance_variable_get(:@challenges)[TEST_SLUG] = dummy
    @registry.enable(TEST_SLUG)
  end

  teardown do
    @registry.instance_variable_set(:@active, @original_active)
    @registry.instance_variable_set(:@challenges, @original_challenges)
    @registry.instance_variable_set(:@applied_routes, @original_applied)
    @registry.instance_variable_set(:@conflict_log, [])
    Rails.application.routes.instance_variable_set(:@prepend, @original_prepend)
    Rails.application.reload_routes!
  end

  # apply_all! が2回実行され @prepend に同じブロックが2つ入った後、
  # clear! が走っても ArgumentError が出ない。
  # （開発モードで Registry Singleton がリセットされ apply_all! が再実行されるシナリオ）
  test "clear! after double apply_all! does not raise ArgumentError" do
    @registry.apply_all!
    # Registry Singleton リセットをシミュレート: @applied_routes をクリアして再適用
    @registry.instance_variable_set(:@applied_routes, Set.new)
    @registry.apply_all!
    # この時点で @prepend に同じブロックが2つ積まれている

    assert_nothing_raised do
      Rails.application.routes.clear!
    end
  end
end
