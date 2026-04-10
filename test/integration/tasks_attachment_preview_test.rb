# frozen_string_literal: true

require "test_helper"

class TasksAttachmentPreviewTest < ActionDispatch::IntegrationTest
  setup do
    ActionController::Base.allow_forgery_protection = false
    @user = User.create!(name: "previewtest", email: "previewtest@example.com", password: "password1234")
    post login_path, params: { email: @user.email, password: "password1234" }
  end

  teardown do
    ActionController::Base.allow_forgery_protection = true
  end

  # ── 画像添付 ──

  test "show renders img tag for image attachment" do
    task = @user.tasks.create!(title: "Image Task")
    task.attachment.attach(
      io: StringIO.new("fake png data"),
      filename: "photo.png",
      content_type: "image/png"
    )

    get task_path(task)

    assert_response :success
    assert_select "img[alt=?]", "photo.png"
  end

  test "show wraps image in a link for full-size viewing" do
    task = @user.tasks.create!(title: "Image Task")
    task.attachment.attach(
      io: StringIO.new("fake jpeg data"),
      filename: "photo.jpg",
      content_type: "image/jpeg"
    )

    get task_path(task)

    assert_response :success
    assert_select "a[target='_blank'][rel='noopener noreferrer'] img[alt=?]", "photo.jpg"
  end

  test "show still shows filename and download link for image attachment" do
    task = @user.tasks.create!(title: "Image Task")
    task.attachment.attach(
      io: StringIO.new("fake png data"),
      filename: "photo.png",
      content_type: "image/png"
    )

    get task_path(task)

    assert_response :success
    assert_select "a[href=?]", download_attachment_task_path(task)
  end

  # ── 非画像添付 ──

  test "show does not render img tag for non-image attachment" do
    task = @user.tasks.create!(title: "PDF Task")
    task.attachment.attach(
      io: StringIO.new("%PDF fake"),
      filename: "document.pdf",
      content_type: "application/pdf"
    )

    get task_path(task)

    assert_response :success
    assert_select "img", count: 0
  end

  test "show shows filename and download link for non-image attachment" do
    task = @user.tasks.create!(title: "Text Task")
    task.attachment.attach(
      io: StringIO.new("hello world"),
      filename: "notes.txt",
      content_type: "text/plain"
    )

    get task_path(task)

    assert_response :success
    assert_select "a[href=?]", download_attachment_task_path(task)
  end

  # ── 添付なし ──

  test "show renders no attachment section when no file attached" do
    task = @user.tasks.create!(title: "No Attachment Task")

    get task_path(task)

    assert_response :success
    assert_select "img", count: 0
    assert_select "a[href=?]", download_attachment_task_path(task), count: 0
  end
end
