# frozen_string_literal: true

require "test_helper"

# claim! が副作用を伴わないチャレンジに対して副作用ゼロで slot を返すことを検証する。
# これらのチャレンジは metadata に slot 宣言を持つため、claim! は apply! を呼ばない。
class ClaimNoSideEffectsTest < ActiveSupport::TestCase
  STATIC_SLOT_CHALLENGES = [
    Vulnerabilities::Challenges::CsrfSkip,
    Vulnerabilities::Challenges::CspDisable,
    Vulnerabilities::Challenges::RegexBypass,
    Vulnerabilities::Challenges::UnsafeFileUpload,
    Vulnerabilities::Challenges::LogLeakage,
    Vulnerabilities::Challenges::HeaderRemoval,
  ].freeze

  STATIC_SLOT_CHALLENGES.each do |klass|
    test "#{klass.slug}: claim! returns non-empty slot list" do
      slots = klass.new.claim!
      assert_kind_of Array, slots
      assert slots.any?, "#{klass.slug}#claim! は少なくとも1つの slot を返す必要があります"
    end

    test "#{klass.slug}: claim! does not invoke apply!" do
      challenge = klass.new
      apply_called = false
      challenge.define_singleton_method(:apply!) { apply_called = true }
      challenge.claim!
      assert_not apply_called, "#{klass.slug}#claim! は apply! を呼んではいけません"
    end
  end

  test "csrf_skip slot name matches declaration" do
    assert_equal ["TasksController.forgery_protection"],
                 Vulnerabilities::Challenges::CsrfSkip.new.claim!
  end

  test "csp_disable slot name matches declaration" do
    assert_equal ["ApplicationController.content_security_policy"],
                 Vulnerabilities::Challenges::CspDisable.new.claim!
  end

  test "regex_bypass slot name matches declaration" do
    assert_equal ["Task.url_format_validator"],
                 Vulnerabilities::Challenges::RegexBypass.new.claim!
  end

  test "unsafe_file_upload slot name matches declaration" do
    assert_equal ["Task.acceptable_attachment_validation"],
                 Vulnerabilities::Challenges::UnsafeFileUpload.new.claim!
  end

  test "log_leakage slot name matches declaration" do
    assert_equal ["Rails.filter_parameters"],
                 Vulnerabilities::Challenges::LogLeakage.new.claim!
  end

  test "header_removal slot name matches declaration" do
    assert_equal ["ApplicationController.security_headers_after_action"],
                 Vulnerabilities::Challenges::HeaderRemoval.new.claim!
  end
end
