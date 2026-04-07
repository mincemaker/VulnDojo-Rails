# frozen_string_literal: true

require "singleton"
require_relative "base"
require_relative "registry"

module Vulnerabilities
  class Engine
    # チャレンジのロード・登録・有効化（起動時に1回、applyはしない）
    def self.setup!
      Dir[File.join(__dir__, "challenges", "*.rb")].each { |f| require f }

      registry = Registry.instance
      Challenges.constants.each do |const_name|
        klass = Challenges.const_get(const_name)
        next unless klass < Base
        registry.register(klass)
      end

      registry.load_from_env!
    end
  end
end
