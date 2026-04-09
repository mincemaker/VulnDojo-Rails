# frozen_string_literal: true

require "test_helper"

class TasksColorDisplayTest < ActionDispatch::IntegrationTest
  setup do
    ActionController::Base.allow_forgery_protection = false
    @user = User.create!(name: "colortest", email: "colortest@example.com", password: "password1234")
    post login_path, params: { email: @user.email, password: "password1234" }

    @task_with_color = @user.tasks.create!(title: "Color Task", color: "#ff5733")
    @task_no_color   = @user.tasks.create!(title: "Plain Task", color: nil)
    @task_bad_color  = @user.tasks.create!(title: "Bad Color Task", color: "red")
  end

  teardown do
    ActionController::Base.allow_forgery_protection = true
  end

  # ── index ──

  test "index shows color indicator next to title for task with valid hex color" do
    get tasks_path
    assert_response :success
    assert_select "td a[href=?] span[style*='background-color:#ff5733']", task_path(@task_with_color)
  end

  test "index does not show color indicator for task without color" do
    get tasks_path
    assert_response :success
    assert_select "td a[href=?]", task_path(@task_no_color) do
      assert_select "span[style*='background-color']", count: 0
    end
  end

  test "index does not show color indicator for task with non-hex color value" do
    get tasks_path
    assert_response :success
    assert_select "td a[href=?]", task_path(@task_bad_color) do
      assert_select "span[style*='background-color']", count: 0
    end
  end

  # ── show ──

  test "show displays color indicator next to title" do
    get task_path(@task_with_color)
    assert_response :success
    assert_select "span[style*='background-color']"
  end

  test "show does not display color indicator when task has no color" do
    get task_path(@task_no_color)
    assert_response :success
    assert_select "span[style*='background-color']", count: 0
  end

  test "show does not display color indicator for non-hex color value" do
    get task_path(@task_bad_color)
    assert_response :success
    assert_select "span[style*='background-color']", count: 0
  end
end
