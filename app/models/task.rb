class Task < ApplicationRecord
  validates :title, presence: true

  attribute :completed, :boolean, default: false
end
