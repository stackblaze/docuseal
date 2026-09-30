# frozen_string_literal: true

require 'net/http'
require 'jwt'

# OpenID Connect sign-in for Google, Microsoft Entra ID, and Okta.
# Uses the authorization code flow with PKCE, state and nonce.
module OidcSso
  PROVIDERS = {
    'google' => { name: 'Google', fields: %w[client_id client_secret] },
    'microsoft' => { name: 'Microsoft', fields: %w[client_id client_secret tenant] },
    'okta' => { name: 'Okta', fields: %w[client_id client_secret domain] }
  }.freeze

  # Multi-tenant Entra endpoints let any tenant assert any email, so a specific tenant is required.
  MICROSOFT_SHARED_TENANTS = %w[common organizations consumers].freeze

  DISCOVERY_TTL = 1.hour
  HTTP_TIMEOUT = 10

  class Error < StandardError; end

  module_function

  def configs_for(account)
    return {} if account.blank?

    value = EncryptedConfig.find_by(account:, key: EncryptedConfig::OIDC_CONFIGS_KEY)&.value
    value.is_a?(Hash) ? value : {}
  end

  def provider_config(account, provider)
    configs_for(account)[provider.to_s] || {}
  end

  def configured?(account, provider)
    return false unless PROVIDERS.key?(provider.to_s)

    config = provider_config(account, provider)
    return false unless config['enabled'] && config['client_id'].present? && config['client_secret'].present?

    issuer(provider, config).present?
  end

  # Account whose settings drive the sign-in page, mirroring Saml.account_with_config.
  def account_with_config
    EncryptedConfig.where(key: EncryptedConfig::OIDC_CONFIGS_KEY).find do |record|
      PROVIDERS.keys.any? { |provider| configured?(record.account, provider) }
    end&.account
  end

  def enabled_providers(account = account_with_config)
    return [] if account.blank?

    PROVIDERS.keys.select { |provider| configured?(account, provider) }
  end

  def any_configured?
    enabled_providers.any?
  end

  def display_name(provider)
    PROVIDERS.dig(provider.to_s, :name) || provider.to_s.titleize
  end

  def issuer(provider, config)
    case provider.to_s
    when 'google'
      'https://accounts.google.com'
    when 'microsoft'
      tenant = config['tenant'].to_s.strip
      return if tenant.blank? || MICROSOFT_SHARED_TENANTS.include?(tenant.downcase)

      "https://login.microsoftonline.com/#{tenant}/v2.0"
    when 'okta'
      okta_issuer(config['domain'])
    end
  end

  # Accepts "acme.okta.com", "https://acme.okta.com", or a custom authorization server issuer URL.
  def okta_issuer(domain)
    value = domain.to_s.strip.chomp('/')
    return if value.blank?

    value = "https://#{value}" unless value.start_with?('https://')
    uri = URI.parse(value)
    uri.host.present? ? value : nil
  rescue URI::InvalidURIError
    nil
  end

  def discovery(issuer)
    Rails.cache.fetch("oidc_discovery:#{issuer}", expires_in: DISCOVERY_TTL) do
      doc = get_json("#{issuer}/.well-known/openid-configuration")
      raise Error, 'discovery document is missing endpoints' if doc['authorization_endpoint'].blank? ||
                                                                doc['token_endpoint'].blank? || doc['jwks_uri'].blank?

      doc
    end
  end

  def authorize_url(account, provider, redirect_uri:, state:, nonce:, code_verifier:)
    config = provider_config(account, provider)
    doc = discovery(issuer(provider, config))
    challenge = Base64.urlsafe_encode64(Digest::SHA256.digest(code_verifier), padding: false)
    query = {
      response_type: 'code',
      client_id: config['client_id'],
      redirect_uri:,
      scope: 'openid email profile',
      state:,
      nonce:,
      code_challenge: challenge,
      code_challenge_method: 'S256'
    }
    query[:prompt] = 'select_account' if provider.to_s.in?(%w[google microsoft])

    "#{doc['authorization_endpoint']}?#{URI.encode_www_form(query)}"
  end

  # Exchanges the code and returns the verified email from the ID token.
  def verified_email(account, provider, code:, redirect_uri:, nonce:, code_verifier:)
    config = provider_config(account, provider)
    expected_issuer = issuer(provider, config)
    doc = discovery(expected_issuer)

    tokens = post_form(doc['token_endpoint'], {
                         grant_type: 'authorization_code',
                         code:,
                         redirect_uri:,
                         client_id: config['client_id'],
                         client_secret: config['client_secret'],
                         code_verifier:
                       })
    id_token = tokens['id_token']
    raise Error, 'token response has no id_token' if id_token.blank?

    # Entra resolves a domain tenant to its GUID issuer, so trust the issuer the tenant's own discovery reports.
    claims = decode_id_token(id_token, doc, doc['issuer'].presence || expected_issuer, config['client_id'])
    raise Error, 'nonce mismatch' unless ActiveSupport::SecurityUtils.secure_compare(claims['nonce'].to_s, nonce.to_s)

    email_from_claims(provider, claims)
  end

  def decode_id_token(id_token, doc, expected_issuer, client_id)
    jwks = lambda do |options|
      Rails.cache.delete("oidc_jwks:#{doc['jwks_uri']}") if options[:kid_not_found]
      Rails.cache.fetch("oidc_jwks:#{doc['jwks_uri']}", expires_in: DISCOVERY_TTL) { get_json(doc['jwks_uri']) }
    end

    payload, = JWT.decode(id_token, nil, true,
                          algorithms: %w[RS256 RS384 RS512 ES256],
                          jwks:,
                          iss: expected_issuer,
                          verify_iss: true,
                          aud: client_id,
                          verify_aud: true,
                          verify_iat: true,
                          leeway: 60)
    payload
  rescue JWT::DecodeError => e
    raise Error, "invalid id_token: #{e.message}"
  end

  def email_from_claims(provider, claims)
    email =
      if provider.to_s == 'microsoft'
        # Entra often omits `email`; the tenant is pinned by the issuer check, so its UPN is trusted.
        claims['email'].presence || claims['preferred_username']
      else
        raise Error, 'email is not verified' if claims.key?('email_verified') && !truthy?(claims['email_verified'])

        claims['email']
      end

    email = email.to_s.strip.downcase
    raise Error, 'id_token has no email' unless email.match?(User::EMAIL_REGEXP)

    email
  end

  def truthy?(value)
    value == true || value.to_s == 'true'
  end

  def get_json(url)
    request_json(URI.parse(url)) { |uri| Net::HTTP::Get.new(uri) }
  end

  def post_form(url, params)
    request_json(URI.parse(url)) do |uri|
      req = Net::HTTP::Post.new(uri)
      req.set_form_data(params)
      req
    end
  end

  def request_json(uri)
    raise Error, "refusing non-https url #{uri}" unless uri.scheme == 'https' || Rails.env.test?

    response = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https',
                                                   open_timeout: HTTP_TIMEOUT, read_timeout: HTTP_TIMEOUT) do |http|
      req = yield(uri)
      req['Accept'] = 'application/json'
      http.request(req)
    end
    body = JSON.parse(response.body.to_s)
    unless response.is_a?(Net::HTTPSuccess)
      raise Error, "#{uri.host} returned #{response.code}: #{body['error_description'] || body['error']}"
    end

    body
  rescue JSON::ParserError
    raise Error, "#{uri.host} returned a non-JSON response"
  end
end
