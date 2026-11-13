# frozen_string_literal: true

require "openssl"
require "fileutils"

module TLSHelper
  DIRECTORY = File.expand_path("../../../.e2e/tls", __dir__)
  CERT = File.join(DIRECTORY, "localhost.crt")
  KEY = File.join(DIRECTORY, "localhost.key")

  def self.prepare!
    if File.file?(CERT) && File.file?(KEY)
      cert = OpenSSL::X509::Certificate.new(File.read(CERT))
      return if cert.not_after > Time.now + 3600
    end

    FileUtils.mkdir_p(DIRECTORY)
    key = OpenSSL::PKey::RSA.new(2048)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = cert.issuer = OpenSSL::X509::Name.parse("/CN=localhost")
    cert.public_key = key.public_key
    cert.not_before = Time.now - 60
    cert.not_after = Time.now + 86_400
    extensions = OpenSSL::X509::ExtensionFactory.new
    extensions.subject_certificate = extensions.issuer_certificate = cert
    cert.add_extension(extensions.create_extension("subjectAltName", "DNS:localhost"))
    cert.sign(key, OpenSSL::Digest::SHA256.new)
    File.write(KEY, key.to_pem, perm: 0o600)
    File.write(CERT, cert.to_pem)
  end

  def self.store
    OpenSSL::X509::Store.new.tap { |store| store.add_file(CERT) }
  end
end
