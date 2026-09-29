# frozen_string_literal: true

module Saml
  module_function

  def config_for(account)
    return {} if account.blank?

    value = EncryptedConfig.find_by(account:, key: EncryptedConfig::SAML_CONFIGS_KEY)&.value
    value.is_a?(Hash) ? value : {}
  end

  def configured?(account = nil)
    account ||= account_with_config
    value = config_for(account)
    value['sso_url'].present? && value['certificate'].present?
  end

  def forced?(account = nil)
    account ||= account_with_config
    return false unless configured?(account)

    AccountConfig.find_by(account:, key: AccountConfig::FORCE_SSO_AUTH_KEY)&.value == true
  end

  def account_with_config
    EncryptedConfig.where(key: EncryptedConfig::SAML_CONFIGS_KEY).find do |record|
      value = record.value
      value.is_a?(Hash) && value['sso_url'].present? && value['certificate'].present?
    end&.account
  end

  def settings_for(account)
    value = config_for(account)
    settings = OneLogin::RubySaml::Settings.new
    options = Docuseal.default_url_options
    settings.assertion_consumer_service_url = routes.saml_url(options)
    settings.sp_entity_id = routes.saml_metadata_url(options)
    settings.idp_sso_service_url = value['sso_url'].to_s
    settings.idp_cert = value['certificate'].to_s
    settings.name_identifier_format = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
    settings.security[:authn_requests_signed] = false
    settings.security[:want_assertions_signed] = false
    settings.security[:want_assertions_encrypted] = false
    settings.security[:metadata_signed] = false
    settings.security[:check_idp_cert_expiration] = true
    settings
  end

  def normalize_certificate(raw)
    text = raw.to_s.strip
    return '' if text.blank?

    body = text.gsub('-----BEGIN CERTIFICATE-----', '')
               .gsub('-----END CERTIFICATE-----', '')
               .gsub(/\s+/, '')
    "-----BEGIN CERTIFICATE-----\n#{body.scan(/.{1,64}/).join("\n")}\n-----END CERTIFICATE-----\n"
  end

  def valid_certificate?(pem)
    OpenSSL::X509::Certificate.new(pem)
    true
  rescue OpenSSL::X509::CertificateError
    false
  end

  def valid_sso_url?(url)
    uri = URI.parse(url.to_s)
    uri.is_a?(URI::HTTP) && uri.host.present?
  rescue URI::InvalidURIError
    false
  end

  def routes
    Rails.application.routes.url_helpers
  end
end
