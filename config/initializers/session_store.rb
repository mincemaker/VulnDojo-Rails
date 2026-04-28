# frozen_string_literal: true

Rails.application.config.session_store :cache_store, key: "_session_id", expire_after: 120.minutes
