# frozen_string_literal: true

module Vulnerabilities
  module Challenges
    class XssStoredImg < Base
      metadata do
        name        "Stored XSS via image caption (html_safe description)"
        category    :xss
        difficulty  :medium
        description "画像を添付したタスクの説明文が html_safe でキャプション表示されています。説明文に XSS ペイロードを入れることで Stored XSS が可能です。"
        hint        "画像を添付したタスクの説明欄を確認してください"
        hint        "説明欄に <img src=x onerror=alert(1)> を入力して画像を添付してみましょう"
        cwe         "CWE-79"
        reference   "https://guides.rubyonrails.org/security.html#cross-site-scripting-xss"
      end

      def apply!
        inject_view "tasks/_task_attachment.html.erb", <<~'ERB'
          <% if @task.attachment.attached? %>
            <div class="detail-row">
              <div class="label">添付ファイル</div>
              <div class="attachment-info">
                <% if @task.attachment.content_type.start_with?("image/") %>
                  <a href="<%= url_for(@task.attachment) %>" target="_blank" rel="noopener noreferrer">
                    <%= image_tag @task.attachment,
                          style: "max-width: 100%; max-height: 400px; object-fit: contain; display: block; margin-bottom: 8px;",
                          alt: @task.attachment.filename.to_s %>
                  </a>
                  <% if @task.description.present? %>
                    <div class="image-caption"><%= @task.description.html_safe %></div>
                  <% end %>
                <% end %>
                📎 <%= @task.attachment.filename %>
                (<%= number_to_human_size(@task.attachment.byte_size) %>)
                <%= link_to "ダウンロード", download_attachment_task_path(@task), class: "btn btn-secondary btn-sm" %>
              </div>
            </div>
          <% end %>
        ERB
      end
    end
  end
end
