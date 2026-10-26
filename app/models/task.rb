# frozen_string_literal: true

class Task < ApplicationRecord
  belongs_to :user
  has_one_attached :attachment

  validates :title, presence: true
  validates :url, format: { with: /^https?:\/\/.+/m, message: "は http:// または https:// で始まる必要があります", multiline: true },
                  allow_blank: true

  attribute :completed, :boolean, default: false

  private

  def acceptable_attachment
  end
end
