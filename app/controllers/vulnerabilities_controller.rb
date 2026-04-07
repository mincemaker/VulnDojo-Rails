# frozen_string_literal: true

class VulnerabilitiesController < ApplicationController
  def dashboard
    @registry = Vulnerabilities::Registry.instance
    @challenges = @registry.all_challenges
  end
end
