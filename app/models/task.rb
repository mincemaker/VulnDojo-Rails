# frozen_string_literal: true

class Task < ApplicationRecord
  belongs_to :user
  has_one_attached :attachment

  validates :title, presence: true
  validates :url, format: { with: /\Ahttps?:\/\/.+\z/, message: "は http:// または https:// で始まる必要があります" },
                  allow_blank: true

  attribute :completed, :boolean, default: false

  # 添付ファイルのバリデーション
  validate :acceptable_attachment

  private

  def acceptable_attachment
    return unless attachment.attached?

    # サイズ上限: 10MB
    if attachment.byte_size > 10.megabytes
      errors.add(:attachment, "は10MB以下にしてください")
    end

    # 許可する MIME タイプ（ホワイトリスト方式）
    acceptable_types = [
      "image/png", "image/jpeg", "image/gif", "image/webp",
      "application/pdf",
      "text/plain", "text/csv"
    ]
    unless acceptable_types.include?(attachment.content_type)
      errors.add(:attachment, "のファイル形式は許可されていません（画像, PDF, テキスト, CSVのみ）")
    end
  end
end
