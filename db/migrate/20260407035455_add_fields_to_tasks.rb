class AddFieldsToTasks < ActiveRecord::Migration[7.1]
  def change
    add_reference :tasks, :user, null: true, foreign_key: true
    add_column :tasks, :url, :string
    add_column :tasks, :secret_note, :text
  end
end
