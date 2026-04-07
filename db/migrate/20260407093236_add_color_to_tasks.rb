class AddColorToTasks < ActiveRecord::Migration[7.1]
  def change
    add_column :tasks, :color, :string
  end
end
