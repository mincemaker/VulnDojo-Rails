# frozen_string_literal: true

require "test_helper"

# Issue #2: apply_all! を複数回呼んでも view_paths に重複が生じないことを検証
# Issue #3: ActionController::Base の descendants にも view_path が伝播することを検証
class ApplyAllViewPathsTest < ActiveSupport::TestCase
  setup do
    @registry = Vulnerabilities::Registry.instance
    @original_active     = @registry.instance_variable_get(:@active).dup
    @original_challenges = @registry.instance_variable_get(:@challenges).dup
    @registry.instance_variable_set(:@active, Set.new)
    @registry.instance_variable_set(:@conflict_log, [])

    # view を inject するダミーチャレンジ
    dummy = Class.new(Vulnerabilities::Base) do
      define_singleton_method(:slug) { "view_path_test_dummy" }
      metadata do
        slot "view:tasks/_view_path_test.html.erb"
      end
      def apply!
        inject_view "tasks/_view_path_test.html.erb", "<div>test</div>"
      end
    end
    @registry.instance_variable_get(:@challenges)["view_path_test_dummy"] = dummy
    @registry.enable("view_path_test_dummy")

    @vuln_view_path = Rails.root.join("lib/vulnerabilities/views").to_s
  end

  teardown do
    @registry.instance_variable_set(:@active, @original_active)
    @registry.instance_variable_set(:@challenges, @original_challenges)
    @registry.instance_variable_set(:@conflict_log, [])
    FileUtils.rm_f(Dir[Rails.root.join("lib/vulnerabilities/views/tasks/_view_path_test.html.erb")])
  end

  # Issue #2: apply_all! を3回呼んでも vuln_view_path の出現回数が1のまま
  test "apply_all! called multiple times does not duplicate view_paths" do
    3.times { @registry.apply_all! }

    count = ActionController::Base.view_paths.map(&:to_s).count(@vuln_view_path)
    assert_equal 1, count, "view_paths に #{@vuln_view_path} が #{count} 回含まれている（期待: 1）"
  end

  # Issue #3: copy-on-write で分離したサブクラスにも view_path が伝播する
  test "apply_all! propagates view_path to descendants that have been split by copy-on-write" do
    # view_paths を明示的に設定することで vuln_view_path を持たない独立したコントローラを作る
    isolated_ctrl = Class.new(ActionController::Base)
    isolated_ctrl.view_paths = [Rails.root.join("app/views").to_s]

    refute_includes isolated_ctrl.view_paths.map(&:to_s), @vuln_view_path,
      "前提: isolated_ctrl は vuln_view_path を持っていないはず"

    @registry.apply_all!

    assert_includes isolated_ctrl.view_paths.map(&:to_s), @vuln_view_path,
      "isolated_ctrl に vuln_view_path が伝播していない"
  end
end
