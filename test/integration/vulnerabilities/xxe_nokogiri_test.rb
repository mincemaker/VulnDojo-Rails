# frozen_string_literal: true

require "test_helper"
require_relative "e2e_helper"

class XxeNokogiriTest < ActiveSupport::TestCase
  include E2EHelper

  setup do
    @safe_server = ServerPool.acquire(vuln_challenges: "")
    @vuln_server = ServerPool.acquire(vuln_challenges: "xxe_nokogiri")
  end

  test "SAFE: normal XML import works correctly" do
    cookie = setup_session(@safe_server)

    xml = <<~XML
      <?xml version="1.0" encoding="UTF-8"?>
      <tasks>
        <task>
          <title>Imported Task</title>
          <description>Task from XML import</description>
          <url>https://example.com</url>
        </task>
      </tasks>
    XML

    res = upload_xml(@safe_server, xml, cookie)
    assert_equal "302", res.code

    tasks_res = @safe_server.get("/tasks", headers: { "Cookie" => cookie })
    assert_match(/インポートしました/, tasks_res.body.force_encoding("UTF-8"))

    # インポートされたタスクのIDを取得して詳細画面を確認
    task_id = extract_task_id(tasks_res.body)
    assert_not_nil task_id, "Imported task ID should be present"

    detail_res = @safe_server.get("/tasks/#{task_id}", headers: { "Cookie" => cookie })
    assert_equal "200", detail_res.code
    assert_match(/Imported Task/, detail_res.body)
    assert_match(/Task from XML import/, detail_res.body)
  end

  test "SAFE: XXE payload is not expanded" do
    cookie = setup_session(@safe_server)

    xxe_payload = <<~XML
      <?xml version="1.0" encoding="UTF-8"?>
      <!DOCTYPE tasks [
        <!ENTITY xxe SYSTEM "file:///etc/passwd">
      ]>
      <tasks>
        <task>
          <title>XXE Test</title>
          <description>&xxe;</description>
        </task>
      </tasks>
    XML

    # First import the malicious XML
    upload_xml(@safe_server, xxe_payload, cookie)

    # Then visit tasks list to see if any task has /etc/passwd content
    res = @safe_server.get("/tasks", headers: { "Cookie" => cookie })
    assert_equal "200", res.code

    # XXE should NOT be expanded, so /etc/passwd content should not appear
    refute_match(/root:/, res.body, "XXE entity should NOT be expanded in safe mode")
    refute_match(/\/bin\/bash/, res.body, "File content from XXE should NOT appear")
  end

  test "VULN: XXE payload is expanded and file content is exposed" do
    cookie = setup_session(@vuln_server)

    xxe_payload = <<~XML
      <?xml version="1.0" encoding="UTF-8"?>
      <!DOCTYPE tasks [
        <!ENTITY xxe SYSTEM "file:///etc/passwd">
      ]>
      <tasks>
        <task>
          <title>XXE Imported</title>
          <description>&xxe;</description>
        </task>
      </tasks>
    XML

    # Import the malicious XML
    upload_xml(@vuln_server, xxe_payload, cookie)

    # Get task list to find the imported task ID
    list_res = @vuln_server.get("/tasks", headers: { "Cookie" => cookie })
    assert_equal "200", list_res.code

    # Extract task ID from the task list page
    task_id = extract_task_id(list_res.body)
    assert_not_nil task_id, "Should have an imported task"

    # Visit task detail page to see the description
    detail_res = @vuln_server.get("/tasks/#{task_id}", headers: { "Cookie" => cookie })
    assert_equal "200", detail_res.code

    # XXE should be expanded, exposing /etc/passwd content
    assert_match(/root:/, detail_res.body, "XXE entity should be expanded in vulnerable mode")
    assert_match(/\/bin\/bash/, detail_res.body, "File content from /etc/passwd should appear via XXE")
  end

  test "VULN: XXE with multiple lines from file is stored" do
    cookie = setup_session(@vuln_server)

    xxe_payload = <<~XML
      <?xml version="1.0" encoding="UTF-8"?>
      <!DOCTYPE tasks [
        <!ENTITY xxe SYSTEM "file:///etc/passwd">
      ]>
      <tasks>
        <task>
          <title>XXE Full Leak</title>
          <description>&xxe;</description>
        </task>
      </tasks>
    XML

    upload_xml(@vuln_server, xxe_payload, cookie)

    list_res = @vuln_server.get("/tasks", headers: { "Cookie" => cookie })
    task_id = extract_task_id(list_res.body)
    assert_not_nil task_id, "Should have an imported task"

    detail_res = @vuln_server.get("/tasks/#{task_id}", headers: { "Cookie" => cookie })
    body = detail_res.body

    # /etc/passwd typically contains lines like "root:x:0:0:..." and "/bin/bash"
    assert_match(/root:/, body, "First line of /etc/passwd should appear")
    assert_match(/\/bin\/(ba)?sh/, body, "Shell path from /etc/passwd should appear")
  end

  private

  def extract_task_id(html)
    # Extract task ID from links like /tasks/123
    match = html.match(%r{href="/tasks/(\d+)"})
    match ? match[1].to_i : nil
  end

  def upload_xml(server, xml_content, cookie)
    # 1. GET /tasks/import_xml to get CSRF token
    res1 = server.get("/tasks/import_xml", headers: { "Cookie" => cookie })
    cookie = latest_cookie(res1, cookie)
    token = extract_csrf_token(res1.body)

    uri = URI("http://127.0.0.1:#{server.port}/tasks/import_xml")
    boundary = "----RubyFormBoundary#{SecureRandom.hex(16)}"

    body = []
    body << "--#{boundary}"
    body << 'Content-Disposition: form-data; name="authenticity_token"'
    body << ""
    body << token
    body << "--#{boundary}"
    body << 'Content-Disposition: form-data; name="xml_file"; filename="tasks.xml"'
    body << "Content-Type: application/xml"
    body << ""
    body << xml_content
    body << "--#{boundary}--"
    body << ""

    req = Net::HTTP::Post.new(uri)
    req["Cookie"] = cookie
    req["Content-Type"] = "multipart/form-data; boundary=#{boundary}"
    req.body = body.join("\r\n")

    Net::HTTP.start(uri.host, uri.port) { |http| http.request(req) }
  end
end
