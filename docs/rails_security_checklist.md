# Rails 7.1 セキュリティチェックリスト — タスク管理アプリ対応版

## 1. Cross-Site Request Forgery (CSRF) Protection

### Vulnerability: CSRF Attacks
**Risk**: Attackers can execute unauthorized commands (create/update/destroy) by tricking authenticated users into submitting malicious requests.

> **✅ このアプリでの実装**: `ApplicationController` inherits from `ActionController::Base` (includes `protect_from_forgery` by default). Layout includes `<%= csrf_meta_tags %>` in `<head>`.

**Mitigations**:
- ✅ Ensure `config.action_controller.default_protect_from_forgery = true` (default in Rails 7.1)
- ✅ Verify `protect_from_forgery with: :exception` is active in `ApplicationController`
- ✅ Include `<%= csrf_meta_tags %>` in `application.html.erb` layout `<head>`
- ✅ Use proper HTTP verbs: GET for queries, POST/PATCH/DELETE for state-changing actions
- ✅ Never use GET requests for create/update/destroy operations
- ⚠️ If using custom AJAX without Turbo/Request.JS, manually add CSRF token header:
  ```ruby
  document.head.querySelector("meta[name=csrf-token]")?.content
  ```

---

## 2. SQL Injection

### Vulnerability: Unsafe Query Construction
**Risk**: Attackers manipulate database queries via user input to bypass authorization, read/modify data, or delete records.

> **✅ このアプリでの実装**: All queries use ActiveRecord hash conditions or scoped associations (`current_user.tasks.find(params[:id])`). No raw SQL interpolation.

**Mitigations**:
- ❌ **NEVER** use string interpolation in queries:
  ```ruby
  # UNSAFE
  Task.where("title = '#{params[:title]}'")
  ```
- ✅ Use parameterized queries with placeholders:
  ```ruby
  # SAFE - positional
  Task.where("title = ? AND status = ?", params[:title], params[:status])

  # SAFE - named
  Task.where("title = :title", title: params[:title])

  # SAFE - hash conditions
  Task.where(title: params[:title], status: params[:status])
  ```
- ✅ Chain ActiveRecord methods instead of raw SQL:
  ```ruby
  current_user.tasks.where("priority >= ?", params[:priority])
  ```
- ⚠️ If you must use `find_by_sql` or `connection.execute`, manually sanitize with `sanitize_sql`

---

## 3. Cross-Site Scripting (XSS)

### Vulnerability: Unsanitized User Input Display
**Risk**: Attackers inject malicious JavaScript that executes in victims' browsers, stealing data or performing unauthorized actions.

> **✅ このアプリでの実装**: All ERB templates use default `<%= %>` escaping. CSP configured with `script_src :self` (no `unsafe-inline`). `HttpOnly` cookies via Rails defaults.

**Mitigations**:
- ✅ Rails escapes output by default in ERB with `<%= %>` - **keep this behavior**
- ❌ **NEVER** use `html_safe` or `raw` on user input:
  ```ruby
  # UNSAFE
  <%= raw @task.description %>
  <%= @task.title.html_safe %>
  ```
- ✅ If you must allow limited HTML formatting, use `sanitize` with permitted tags:
  ```ruby
  <%= sanitize @task.description,
       tags: %w(strong em a p br),
       attributes: %w(href title) %>
  ```
- ✅ For plain text that needs HTML entities preserved, just use default escaping: `<%= @task.title %>`
- ⚠️ Be cautious with link helpers:
  ```ruby
  # Vulnerable if @task.url is user input
  <%= link_to "Visit", @task.url %>

  # Safer - validate URLs (see section 11)
  ```
- ✅ Set `HttpOnly` cookies (Rails default) to prevent JavaScript access to session cookies

---

## 4. Mass Assignment / Strong Parameters

### Vulnerability: Unprotected Attribute Assignment
**Risk**: Attackers modify unintended model attributes (e.g., `admin: true`, `user_id: other_user_id`) by injecting extra parameters.

> **✅ このアプリでの実装**: `TasksController#task_params` permits only `:title, :description, :completed, :due_date, :url, :secret_note, :attachment`. `UsersController#user_params` permits only `:name, :email, :password, :password_confirmation`. `user_id` is never in the permit list — it is set via `current_user.tasks.build`.

**Mitigations**:
- ✅ **Always** use strong parameters in controllers:
  ```ruby
  # app/controllers/tasks_controller.rb
  def task_params
    params.require(:task).permit(:title, :description, :completed, :due_date, :url, :secret_note, :attachment, :color)
  end

  # Use in actions — note user_id is NEVER permitted
  @task = current_user.tasks.build(task_params)
  @task.update(task_params)
  ```
- ❌ **NEVER** pass `params` directly to model methods:
  ```ruby
  # UNSAFE
  Task.create(params[:task])
  @task.update(params[:task])
  ```
- ✅ Use **permitted lists** only - explicitly allow safe attributes
- ❌ Don't use `permit!` which permits all attributes

---

## 5. Privilege Escalation / IDOR Prevention

### Vulnerability: Parameter Tampering (Insecure Direct Object Reference)
**Risk**: Users modify IDs or other parameters in URLs/forms to access/modify records they shouldn't control.

> **✅ このアプリでの実装**: `TasksController#set_task` uses `current_user.tasks.find(params[:id])` for all member actions. `index`, `new`, and `export` are also scoped to `current_user.tasks`. Authentication is enforced via `before_action :require_login` in `ApplicationController`.

**Mitigations**:
- ❌ **NEVER** trust `params[:id]` alone:
  ```ruby
  # UNSAFE - any user can edit any task
  @task = Task.find(params[:id])
  ```
- ✅ Scope queries to the authenticated user:
  ```ruby
  # app/controllers/tasks_controller.rb
  def set_task
    @task = current_user.tasks.find(params[:id])
  end
  ```
- ✅ For multi-step operations, re-verify authorization at each step
- ⚠️ Don't rely on hiding/obfuscating IDs - always enforce server-side checks

---

## 6. Session Storage Security

### Vulnerability: Session Data Exposure/Tampering
**Risk**: Sensitive data leakage or session replay attacks.

> **✅ このアプリでの実装**: `ActiveRecordStore` (`activerecord-session_store` gem). Session ID is stored server-side in the `sessions` table; only a token is sent in the cookie. Session stores only `user_id`. Secrets managed via `config/credentials.yml.enc`.

**Mitigations**:
- ✅ Uses `ActiveRecordStore` — session data is stored server-side, not in the cookie
- ✅ Ensure `secret_key_base` is set in `config/credentials.yml.enc`:
  ```bash
  bin/rails credentials:edit
  ```
- ❌ **NEVER** hardcode secrets or commit `config/master.key`
- ⚠️ Don't store sensitive data in sessions (4KB limit, client-side storage):
  ```ruby
  # Avoid storing large or sensitive data
  session[:credit_card] = params[:cc]  # BAD

  # Store IDs/references only
  session[:user_id] = @user.id  # Good (this app does this)
  ```
- ✅ For value-based data (credits, balances), store in database, not sessions

---

## 7. Session Fixation

### Vulnerability: Attacker Forces Known Session ID
**Risk**: Attackers can hijack sessions if IDs aren't regenerated when privilege levels change.

> **✅ このアプリでの実装**: `SessionsController#create` calls `reset_session` before setting `session[:user_id]` on login. `SessionsController#destroy` calls `reset_session` on logout. `UsersController#create` calls `reset_session` before setting session on signup.

**Mitigations**:
- ✅ Call `reset_session` when privilege level changes:
  ```ruby
  # app/controllers/sessions_controller.rb
  def create
    user = User.find_by(email: params[:email]&.downcase)
    if user&.authenticate(params[:password])
      reset_session                  # Prevent session fixation
      session[:user_id] = user.id
      redirect_to tasks_path
    else
      # ...
    end
  end

  def destroy
    reset_session                    # Clear session on logout
    redirect_to login_path
  end
  ```
- ✅ Also reset on signup:
  ```ruby
  # app/controllers/users_controller.rb
  def create
    @user = User.new(user_params)
    if @user.save
      reset_session
      session[:user_id] = @user.id
      # ...
    end
  end
  ```

---

## 8. Unsafe Redirects

### Vulnerability: Open Redirect
**Risk**: Attackers redirect users to phishing sites or inject headers.

> **✅ このアプリでの実装**: `ApplicationController#safe_redirect_to` validates that the URL starts with `/` and does not start with `//` (which browsers treat as protocol-relative external URLs). Used in `TasksController#create` and `#update` for the `return_to` parameter.

**Mitigations**:
- ❌ **NEVER** pass user input directly to `redirect_to`:
  ```ruby
  # UNSAFE
  redirect_to params[:return_to]
  redirect_to params[:url]
  ```
- ✅ Validate redirect URLs are internal paths only:
  ```ruby
  # app/controllers/application_controller.rb
  def safe_redirect_to(url, fallback:)
    if url.present? && url.start_with?("/") && !url.start_with?("//")
      redirect_to url
    else
      redirect_to fallback
    end
  end
  ```
- ✅ Use in controllers:
  ```ruby
  safe_redirect_to params[:return_to], fallback: @task
  ```
- ✅ Prefer named route helpers (`tasks_path`, `root_path`) for static redirects

---

## 9. Command Line Injection

### Vulnerability: Unsafe System Command Execution
**Risk**: Attackers execute arbitrary OS commands if user input is passed to shell.

> **✅ このアプリでの実装**: CSV export uses `CSV.generate` (pure Ruby, no shell commands). No `system`, backtick, or `exec` calls anywhere in the app.

**Mitigations**:
- ❌ **NEVER** interpolate user input into system commands:
  ```ruby
  # UNSAFE
  system("grep #{params[:search]} tasks.log")
  `rm #{params[:filename]}`
  ```
- ✅ Use array syntax to pass parameters safely:
  ```ruby
  # SAFE
  system("grep", params[:search], "tasks.log")
  ```
- ⚠️ Avoid `Kernel#open` with user input (can execute commands with `| ls` syntax):
  ```ruby
  # Use File.open, IO.open, or URI#open instead
  File.open(filename) { |f| f.read }  # Safe
  ```

---

## 10. Header Injection

### Vulnerability: CRLF Injection in HTTP Headers
**Risk**: Attackers inject malicious headers or cause response splitting.

> **✅ このアプリでの実装**: Host authorization configured in `config/environments/development.rb` with `config.hosts = ["localhost", "127.0.0.1", "::1"]`. Rails 7.1 escapes CRLF in `redirect_to` by default.

**Mitigations**:
- ✅ Rails 2.1.2+ escapes CRLF in `redirect_to` - ensure you're on Rails 7.1
- ⚠️ If building custom headers, sanitize user input:
  ```ruby
  # Be cautious with custom headers
  response.headers['X-Custom'] = params[:value].gsub(/[\r\n]/, '')
  ```
- ✅ Enable `ActionDispatch::HostAuthorization`:
  ```ruby
  # config/environments/development.rb
  config.hosts = ["localhost", "127.0.0.1", "::1"]
  ```

---

## 11. Regular Expression Pitfalls

### Vulnerability: Incorrect Anchor Usage
**Risk**: Validation bypasses allowing malicious input (XSS, injection).

> **✅ このアプリでの実装**: `Task` model URL validation uses `\A` and `\z` anchors: `validates :url, format: { with: /\Ahttps?:\/\/.+\z/ }`. `User` model email validation also uses `\A` and `\z`.

**Mitigations**:
- ❌ **NEVER** use `^` and `$` for string start/end in validations:
  ```ruby
  # UNSAFE - matches line start/end, not string
  validates :url, format: { with: /^https?:\/\/.+$/ }
  ```
- ✅ Use `\A` and `\z` for string start/end:
  ```ruby
  # app/models/task.rb
  validates :url, format: { with: /\Ahttps?:\/\/.+\z/ }, allow_blank: true

  # app/models/user.rb
  validates :email, format: { with: /\A[\w+\-.]+@[a-z\d\-.]+\.[a-z]+\z/i }
  ```
- ✅ Rails format validator raises exception if you use `^`/`$` without `multiline: true`

---

## 12. Unsafe Query Generation (Deep Munge)

### Vulnerability: IS NULL Injection via Array Parameters
**Risk**: Attackers bypass nil checks by sending `[nil]` or `['foo', nil]` in parameters.

> **✅ このアプリでの実装**: Default `perform_deep_munge = true` is active (Rails default, not overridden).

**Mitigations**:
- ✅ Keep default `config.action_dispatch.perform_deep_munge = true` (Rails default)
- ⚠️ If you disable deep_munge, manually handle nil arrays:
  ```ruby
  # Vulnerable if deep_munge disabled
  unless params[:token].nil?
    user = User.find_by_token(params[:token])
  end

  # Attacker sends params[:token] = [nil] to bypass check
  ```

---

## 13. CSS Injection

### Vulnerability: Malicious CSS with JavaScript
**Risk**: JavaScript execution via CSS (older browsers: IE, Safari) or CSS-based attacks.

> **✅ このアプリでの実装**: The task label color is user-controlled but validated against `/\A#[0-9a-fA-F]{3,6}\z/` before embedding in a `style` attribute. Only valid hex color codes are rendered inline; arbitrary CSS is rejected. CSP includes `style_src :self, :unsafe_inline` (required for the safe color swatch display).

**Mitigations**:
- ❌ **NEVER** allow user-controlled CSS:
  ```ruby
  # UNSAFE
  <div style="<%= params[:style] %>">
  ```
- ✅ If custom styling needed, use predefined classes or validated color values:
  ```ruby
  # Safe approach
  ALLOWED_COLORS = %w(red blue green)
  color = ALLOWED_COLORS.include?(params[:color]) ? params[:color] : 'black'
  ```

---

## 14. HTTP Security Headers

### Vulnerability: Missing Security Headers
**Risk**: Clickjacking, MIME sniffing attacks, XSS in older browsers.

> **✅ このアプリでの実装**: Rails 7.1 default headers are active (`X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`, etc.). CSP `frame_ancestors :none` provides additional clickjacking protection.

**Mitigations**:
- ✅ Verify default headers in `config/application.rb` (Rails 7.1 defaults):
  ```ruby
  config.action_dispatch.default_headers = {
    'X-Frame-Options' => 'SAMEORIGIN',
    'X-Content-Type-Options' => 'nosniff',
    'X-Permitted-Cross-Domain-Policies' => 'none',
    'Referrer-Policy' => 'strict-origin-when-cross-origin'
  }
  ```
- ✅ Enable HTTPS in production:
  ```ruby
  # config/environments/production.rb
  config.force_ssl = true
  ```

---

## 15. Content Security Policy (CSP)

### Vulnerability: XSS via Inline Scripts
**Risk**: Even with output escaping, injected inline event handlers can execute.

> **✅ このアプリでの実装**: CSP configured in `config/initializers/content_security_policy.rb` with strict directives: `default_src :self`, `script_src :self`, `object_src :none`, `base_uri :self`, `form_action :self`, `frame_ancestors :none`.

**Mitigations**:
- ✅ Configure CSP in `config/initializers/content_security_policy.rb`:
  ```ruby
  # Actual configuration in this app
  Rails.application.configure do
    config.content_security_policy do |policy|
      policy.default_src :self
      policy.font_src    :self, :data
      policy.img_src     :self, :data
      policy.object_src  :none
      policy.script_src  :self
      policy.style_src   :self, :unsafe_inline
      policy.base_uri    :self
      policy.form_action :self
      policy.frame_ancestors :none
    end
  end
  ```
- ⚠️ Consider using nonces for inline scripts instead of `unsafe-inline`:
  ```ruby
  # In initializer
  Rails.application.config.content_security_policy_nonce_generator =
    ->(request) { SecureRandom.base64(16) }

  # In views
  <%= javascript_tag nonce: true do %>
    // your inline JS
  <% end %>
  ```

---

## 16. Logging Sensitive Data

### Vulnerability: Secrets in Log Files
**Risk**: Credentials, tokens, or PII exposed in logs accessible to attackers.

> **✅ このアプリでの実装**: `config/initializers/filter_parameter_logging.rb` filters `:passw, :secret, :token, :_key, :crypt, :salt, :certificate, :otp, :ssn, :secret_note`. The `:secret_note` field (a task attribute) is explicitly filtered.

**Mitigations**:
- ✅ Configure parameter filtering in `config/initializers/filter_parameter_logging.rb`:
  ```ruby
  # Actual configuration in this app
  Rails.application.config.filter_parameters += [
    :passw, :secret, :token, :_key, :crypt, :salt, :certificate, :otp, :ssn,
    :secret_note
  ]
  ```
- ⚠️ Parameters show as `[FILTERED]` in logs
- ✅ Add any new sensitive model attributes to this list as they are introduced

---

## 17. Environmental Security

### Vulnerability: Exposed Secrets in Version Control
**Risk**: Database credentials, API keys compromised if committed.

> **✅ このアプリでの実装**: Secrets stored in `config/credentials.yml.enc` (encrypted). `config/master.key` is in `.gitignore`.

**Mitigations**:
- ✅ Use encrypted credentials (Rails 7.1 default):
  ```bash
  bin/rails credentials:edit
  # Add secrets here, stored in config/credentials.yml.enc
  ```
- ❌ **NEVER** commit `config/master.key` or `.env` files
- ✅ Add to `.gitignore`:
  ```
  /config/master.key
  /config/credentials/*.key
  .env
  .env.local
  ```
- ✅ Use environment variables for production:
  ```ruby
  ENV['RAILS_MASTER_KEY']
  ```
- ⚠️ Secure `config/database.yml` - don't commit production credentials

---

## 18. Dependency Management (CVEs)

### Vulnerability: Vulnerable Gem Dependencies
**Risk**: Exploits in outdated gems (Rails, SQLite3, bcrypt, etc.).

> **✅ このアプリでの実装**: Uses `bcrypt` for password hashing via `has_secure_password`. Keep all gems up to date, especially `rails`, `bcrypt`, and `sqlite3`.

**Mitigations**:
- ✅ Regularly update gems:
  ```bash
  bundle update --conservative gem_name
  bundle audit check --update
  ```
- ✅ Subscribe to security announcements:
  - Rails security mailing list: https://groups.google.com/forum/#!forum/rubyonrails-security
- ✅ Use Bundler Audit:
  ```bash
  gem install bundler-audit
  bundle audit check
  ```
- ✅ Monitor GitHub Security Advisories for your repository

---

## 19. Intranet/Admin Security

### Vulnerability: Privileged Interface Attacks
**Risk**: Admin actions vulnerable to XSS/CSRF affect entire application.

> **ℹ️ このアプリでの実装**: No admin interface currently exists. All users have equal privileges over their own tasks. If admin features are added, apply the mitigations below.

**Mitigations**:
- ✅ Apply **ALL** XSS protections to admin views (sanitize, escape output)
- ✅ Ensure CSRF protection on admin destroy/update actions
- ⚠️ Consider IP-based restrictions for admin routes:
  ```ruby
  # config/routes.rb
  constraints(ip: /192\.168\.1\.\d+/) do
    namespace :admin do
      resources :tasks
    end
  end
  ```
- ✅ Use subdomain isolation if possible: `admin.yourdomain.com`

---

## 20. Permitted Lists vs Restricted Lists

### Principle: Secure by Default Approach
**Risk**: Restricted lists are never complete; attackers find bypasses.

> **✅ このアプリでの実装**: Permitted-list pattern used throughout — strong parameters (`permit` explicit fields), file upload MIME whitelist, `safe_redirect_to` path validation, `before_action :require_login` with explicit `skip_before_action` only where needed.

**Mitigations**:
- ✅ Use **permitted lists** (allow known-good) instead of restricted lists (block known-bad):
  ```ruby
  # Good - permit known safe attributes
  params.require(:task).permit(:title, :description)

  # Good - allow safe HTML tags
  sanitize(input, tags: %w(strong em p))

  # Good - require authentication by default, skip explicitly
  before_action :require_login
  skip_before_action :require_login, only: %i[new create]  # Only for public actions
  ```

---

## 21. File Upload Security

### Vulnerability: Malicious File Uploads
**Risk**: Attackers upload executable files, oversized files causing DoS, or files with spoofed MIME types to exploit downstream processing.

> **✅ このアプリでの実装**: `Task` model validates attachments with a MIME type whitelist and 10MB size limit. Active Storage uses Disk service. Downloads use `allow_other_host: false`.

**Mitigations**:
- ✅ Validate MIME types with a **permitted list** (never a blocklist):
  ```ruby
  # app/models/task.rb
  def acceptable_attachment
    return unless attachment.attached?

    # Size limit: 10MB
    if attachment.byte_size > 10.megabytes
      errors.add(:attachment, "は10MB以下にしてください")
    end

    # Allowed MIME types (whitelist)
    acceptable_types = [
      "image/png", "image/jpeg", "image/gif", "image/webp",
      "application/pdf",
      "text/plain", "text/csv"
    ]
    unless acceptable_types.include?(attachment.content_type)
      errors.add(:attachment, "のファイル形式は許可されていません")
    end
  end
  ```
- ✅ Enforce file size limits to prevent denial-of-service
- ✅ Serve downloads via redirect with `allow_other_host: false`:
  ```ruby
  # app/controllers/tasks_controller.rb
  def download_attachment
    if @task.attachment.attached?
      redirect_to rails_blob_path(@task.attachment, disposition: "attachment"),
                  allow_other_host: false
    else
      redirect_to @task, alert: "添付ファイルがありません。"
    end
  end
  ```
- ✅ Attachment downloads are scoped through `set_task` (which uses `current_user.tasks.find`) — other users cannot download your attachments
- ⚠️ In production, consider using a cloud storage service (S3, GCS) instead of Disk to isolate uploaded files from the application server
- ⚠️ Consider validating file content (magic bytes) in addition to declared MIME type for defense in depth

---

## Quick Setup Checklist — Current Implementation Status

```ruby
# 1. ✅ Authentication (app/controllers/application_controller.rb)
before_action :require_login
# User model with has_secure_password (bcrypt)

# 2. ✅ CSRF protection (Rails default + layout)
# ApplicationController < ActionController::Base (includes protect_from_forgery)
<%= csrf_meta_tags %>  # in application.html.erb

# 3. ✅ IDOR prevention (app/controllers/tasks_controller.rb)
def set_task
  @task = current_user.tasks.find(params[:id])  # Owner-scoped
end

# 4. ✅ Strong parameters (app/controllers/tasks_controller.rb)
def task_params
  params.require(:task).permit(:title, :description, :completed, :due_date, :url, :secret_note, :attachment, :color)
end

# 5. ✅ Session fixation prevention (app/controllers/sessions_controller.rb)
reset_session  # Called before setting session[:user_id] on login, logout, and signup

# 6. ✅ Safe redirects (app/controllers/application_controller.rb)
def safe_redirect_to(url, fallback:)
  if url.present? && url.start_with?("/") && !url.start_with?("//")
    redirect_to url
  else
    redirect_to fallback
  end
end

# 7. ✅ URL validation with correct anchors (app/models/task.rb)
validates :url, format: { with: /\Ahttps?:\/\/.+\z/ }, allow_blank: true

# 8. ✅ File upload security (app/models/task.rb)
# MIME whitelist + 10MB size limit + allow_other_host: false on downloads

# 9. ✅ Log filtering (config/initializers/filter_parameter_logging.rb)
config.filter_parameters += [:passw, :secret, :token, :_key, :crypt, :salt,
                             :certificate, :otp, :ssn, :secret_note]

# 10. ✅ CSP (config/initializers/content_security_policy.rb)
# default_src :self, script_src :self, object_src :none,
# base_uri :self, form_action :self, frame_ancestors :none

# 11. ✅ Host authorization (config/environments/development.rb)
config.hosts = ["localhost", "127.0.0.1", "::1"]

# 12. ✅ Force SSL in production (config/environments/production.rb)
config.force_ssl = true

# 13. ✅ Encrypted credentials
bin/rails credentials:edit  # Secrets in config/credentials.yml.enc

# 14. ✅ CSV export — pure Ruby, no shell commands
CSV.generate(headers: true) { |csv| ... }

# 15. Keep dependencies updated
bundle update --conservative
bundle audit check
```

---

## Testing Security

```ruby
# Test CSRF protection
test "should block create without CSRF token" do
  assert_no_difference('Task.count') do
    post tasks_url, params: { task: { title: 'Test' } },
                     headers: { 'X-CSRF-Token' => 'invalid' }
  end
end

# Test IDOR prevention
test "should not allow access to other user's task" do
  other_task = tasks(:other_user_task)
  get task_url(other_task)
  assert_response :not_found  # or redirect, depending on error handling
end

# Test authentication required
test "should redirect to login when not authenticated" do
  get tasks_url
  assert_redirected_to login_path
end

# Test session fixation prevention
test "should regenerate session on login" do
  old_session_id = session.id
  post login_url, params: { email: @user.email, password: 'password' }
  assert_not_equal old_session_id, session.id
end

# Test file upload validation
test "should reject oversized attachment" do
  large_file = fixture_file_upload('large_file.bin', 'application/octet-stream')
  post tasks_url, params: { task: { title: 'Test', attachment: large_file } }
  assert_response :unprocessable_entity
end

# Test safe redirect
test "should not redirect to external URL" do
  post tasks_url, params: { task: { title: 'Test' }, return_to: 'https://evil.com' }
  assert_redirected_to task_url(Task.last)  # Falls back to default
end

# Test SQL injection resistance
test "should not be vulnerable to SQL injection" do
  get tasks_url, params: { search: "' OR 1=1--" }
  assert_response :success
end

# Test XSS escaping
test "should escape malicious task titles" do
  task = Task.create(title: "<script>alert('xss')</script>", user: @user)
  get task_url(task)
  assert_select "script", count: 0
  assert_match "&lt;script&gt;", response.body
end
```

---

This checklist covers security concerns for a Rails 7.1 task management app with authentication (`has_secure_password`), owner-scoped data access, file attachments (Active Storage), and session management. Prioritize keeping authentication, IDOR prevention, strong parameters, CSRF protection, and file upload validation as your baseline security measures. Regularly audit dependencies and review new features against this checklist.
