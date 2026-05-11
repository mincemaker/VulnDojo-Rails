# frozen_string_literal: true

ActiveModel::SecurePassword.min_cost = false
BCrypt::Engine.cost = 10
