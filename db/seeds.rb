# frozen_string_literal: true

# テスト用デフォルトユーザ
user = User.find_or_create_by!(email: "demo@example.com") do |u|
  u.name = "デモユーザ"
  u.password = "password123"
  u.password_confirmation = "password123"
end

puts "デモユーザ: demo@example.com / password123"
