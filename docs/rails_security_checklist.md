# Rails 7.1 Security Checklist for Simple CRUD Apps

## 1. Cross-Site Request Forgery (CSRF) Protection

### Vulnerability: CSRF Attacks
**Risk**: Attackers can execute unauthorized commands (create/update/destroy) by tricking authenticated users into submitting malicious requests.

**Mitigations**:
- ✅ Ensure `config.action_controller.default_protect_from_forgery = true` (default in Rails 7.1)
- ✅ Verify `protect_from_forgery with: :exception` is in `ApplicationController`
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
  Task.where(user_id: current_user_id).where("priority >= ?", params[:priority])
  ```
- ⚠️ If you must use `find_by_sql` or `connection.execute`, manually sanitize with `sanitize_sql`

---

## 3. Cross-Site Scripting (XSS)

### Vulnerability: Unsanitized User Input Display
**Risk**: Attackers inject malicious JavaScript that executes in victims' browsers, stealing data or performing unauthorized actions.

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
  
  # Safer - validate URLs or use permitted list
  ```
- ✅ Set `HttpOnly` cookies (Rails default) to prevent JavaScript access to session cookies

---

## 4. Mass Assignment / Strong Parameters

### Vulnerability: Unprotected Attribute Assignment
**Risk**: Attackers modify unintended model attributes (e.g., `admin: true`, `user_id: other_user_id`) by injecting extra parameters.

**Mitigations**:
- ✅ **Always** use strong parameters in controllers:
  ```ruby
  # tasks_controller.rb
  private
  def task_params
    params.require(:task).permit(:title, :description, :due_date, :completed)
  end
  
  # Use in actions
  @task = Task.new(task_params)
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

## 5. Privilege Escalation

### Vulnerability: Parameter Tampering
**Risk**: Users modify IDs or other parameters in URLs/forms to access/modify records they shouldn't control.

**Mitigations**:
- ❌ **NEVER** trust `params[:id]` alone:
  ```ruby
  # UNSAFE - any user can edit any task
  @task = Task.find(params[:id])
  ```
- ✅ Scope queries to current user/context (even without authentication, use session-based ownership):
  ```ruby
  # Better - limit to user's records
  @task = current_user.tasks.find(params[:id])
  
  # Or for session-based ownership:
  @task = Task.where(session_id: session.id).find(params[:id])
  ```
- ✅ For multi-step operations, re-verify authorization at each step
- ⚠️ Don't rely on hiding/obfuscating IDs - always enforce server-side checks

---

## 6. Session Storage Security

### Vulnerability: Session Data Exposure/Tampering
**Risk**: Sensitive data leakage or session replay attacks.

**Mitigations**:
- ✅ Rails 7.1 uses encrypted `CookieStore` by default - keep this
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
  session[:user_id] = @user.id  # Better
  ```
- ✅ For value-based data (credits, balances), store in database, not sessions
- ✅ Use separate salt values - don't change defaults in `config/initializers/cookies_serializer.rb`

---

## 7. Session Fixation

### Vulnerability: Attacker Forces Known Session ID
**Risk**: Even without login, attackers can hijack sessions if IDs aren't regenerated.

**Mitigations**:
- ✅ Call `reset_session` when privilege level changes:
  ```ruby
  # Example: When user gains admin access via session
  def promote_to_admin
    reset_session
    session[:admin] = true
    # ... transfer necessary session data
  end
  ```
- ⚠️ For apps without authentication, consider regenerating sessions periodically or on critical actions

---

## 8. Unsafe Redirects

### Vulnerability: Open Redirect
**Risk**: Attackers redirect users to phishing sites or inject headers.

**Mitigations**:
- ❌ **NEVER** pass user input directly to `redirect_to`:
  ```ruby
  # UNSAFE
  redirect_to params[:return_to]
  redirect_to params[:url]
  ```
- ✅ Use permitted list or validate URLs:
  ```ruby
  # Safe approach
  ALLOWED_REDIRECTS = ['/tasks', '/dashboard', '/']
  
  def safe_redirect
    path = params[:return_to]
    if ALLOWED_REDIRECTS.include?(path)
      redirect_to path
    else
      redirect_to root_path
    end
  end
  ```
- ✅ Or use relative paths only:
  ```ruby
  redirect_to tasks_path
  redirect_to root_path
  ```
- ⚠️ Validate that redirect URLs start with `/` and don't contain `://` to prevent external redirects

---

## 9. Command Line Injection

### Vulnerability: Unsafe System Command Execution
**Risk**: Attackers execute arbitrary OS commands if user input is passed to shell.

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

**Mitigations**:
- ✅ Rails 2.1.2+ escapes CRLF in `redirect_to` - ensure you're on Rails 7.1
- ⚠️ If building custom headers, sanitize user input:
  ```ruby
  # Be cautious with custom headers
  response.headers['X-Custom'] = params[:value].gsub(/[\r\n]/, '')
  ```
- ✅ Enable `ActionDispatch::HostAuthorization` (default in development):
  ```ruby
  # config/application.rb
  config.hosts << "yourdomain.com"
  config.hosts << "www.yourdomain.com"
  ```

---

## 11. Regular Expression Pitfalls

### Vulnerability: Incorrect Anchor Usage
**Risk**: Validation bypasses allowing malicious input (XSS, injection).

**Mitigations**:
- ❌ **NEVER** use `^` and `$` for string start/end in validations:
  ```ruby
  # UNSAFE - matches line start/end, not string
  validates :url, format: { with: /^https?:\/\/.+$/ }
  ```
- ✅ Use `\A` and `\z` for string start/end:
  ```ruby
  # SAFE
  validates :url, format: { with: /\Ahttps?:\/\/.+\z/ }
  ```
- ✅ Rails format validator raises exception if you use `^`/`$` without `multiline: true`

---

## 12. Unsafe Query Generation (Deep Munge)

### Vulnerability: IS NULL Injection via Array Parameters
**Risk**: Attackers bypass nil checks by sending `[nil]` or `['foo', nil]` in parameters.

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
- ⚠️ Consider stricter `X-Frame-Options`:
  ```ruby
  config.action_dispatch.default_headers['X-Frame-Options'] = 'DENY'
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

**Mitigations**:
- ✅ Configure CSP in `config/initializers/content_security_policy.rb`:
  ```ruby
  Rails.application.config.content_security_policy do |policy|
    policy.default_src :self, :https
    policy.font_src    :self, :https, :data
    policy.img_src     :self, :https, :data
    policy.object_src  :none
    policy.script_src  :self, :https
    policy.style_src   :self, :https
    # For reporting violations
    policy.report_uri "/csp-violation-report-endpoint"
  end
  ```
- ✅ Use nonces for inline scripts instead of `unsafe-inline`:
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

**Mitigations**:
- ✅ Configure parameter filtering in `config/initializers/filter_parameter_logging.rb`:
  ```ruby
  Rails.application.config.filter_parameters += [
    :password, :password_confirmation, :secret, :token,
    :api_key, :credit_card, :ssn
  ]
  ```
- ✅ Add custom sensitive params for your Task model:
  ```ruby
  config.filter_parameters += [:private_notes, :confidential_data]
  ```
- ⚠️ Parameters show as `[FILTERED]` in logs

---

## 17. Environmental Security

### Vulnerability: Exposed Secrets in Version Control
**Risk**: Database credentials, API keys compromised if committed.

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
**Risk**: Exploits in outdated gems (Rails, SQLite3, etc.).

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

**Mitigations**:
- ✅ Use **permitted lists** (allow known-good) instead of restricted lists (block known-bad):
  ```ruby
  # Good - permit known safe attributes
  params.require(:task).permit(:title, :description)
  
  # Good - allow safe HTML tags
  sanitize(input, tags: %w(strong em p))
  
  # Good - controller filters
  before_action :authenticate, except: [:index, :show]
  # Better than: only: [:create, :update, :destroy]
  ```

---

## Quick Setup Checklist for New Rails 7.1 CRUD App

```ruby
# 1. Verify CSRF protection (ApplicationController)
protect_from_forgery with: :exception

# 2. Add CSRF meta tags (app/views/layouts/application.html.erb)
<%= csrf_meta_tags %>

# 3. Configure strong parameters (TasksController)
def task_params
  params.require(:task).permit(:title, :description, :due_date, :completed)
end

# 4. Filter logs (config/initializers/filter_parameter_logging.rb)
Rails.application.config.filter_parameters += [:secret_field]

# 5. Enable force_ssl in production (config/environments/production.rb)
config.force_ssl = true

# 6. Configure CSP (config/initializers/content_security_policy.rb)
Rails.application.config.content_security_policy do |policy|
  policy.default_src :self, :https
  policy.script_src  :self, :https
  # ... etc
end

# 7. Verify host authorization (config/application.rb)
config.hosts << "yourdomain.com"

# 8. Secure credentials (run once)
bin/rails credentials:edit
# Add: secret_key_base, database passwords

# 9. Update dependencies regularly
bundle update --conservative
bundle audit check

# 10. Review queries - use parameterized queries only
Task.where("status = ?", params[:status])  # Good
# Never: Task.where("status = '#{params[:status]}'")  # Bad
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

# Test SQL injection resistance
test "should not be vulnerable to SQL injection" do
  get tasks_url, params: { search: "' OR 1=1--" }
  assert_response :success
  # Verify it doesn't return all tasks
end

# Test XSS escaping
test "should escape malicious task titles" do
  task = Task.create(title: "<script>alert('xss')</script>")
  get task_url(task)
  assert_select "script", count: 0
  assert_match "&lt;script&gt;", response.body
end
```

---

This checklist covers all major security concerns for a simple Rails 7.1 scaffold-generated CRUD app without authentication. Prioritize implementing strong parameters, CSRF protection, parameterized queries, and output escaping as your baseline security measures.