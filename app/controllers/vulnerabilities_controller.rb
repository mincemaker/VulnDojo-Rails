# frozen_string_literal: true

class VulnerabilitiesController < ApplicationController
  def dashboard
    @registry = Vulnerabilities::Registry.instance
  end
end
