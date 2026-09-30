# frozen_string_literal: true

RSpec.describe 'SSO sign-in' do
  let(:account) { create(:account) }
  let!(:user) { create(:user, account:, email: 'jane@example.com', password: 'strong_password') }

  def signed_in?
    get '/settings/profile'
    response.successful?
  end

  describe 'OpenID Connect' do
    let(:key) { OpenSSL::PKey::RSA.generate(2048) }
    let(:jwk) { JWT::JWK.new(key, kid: 'k1') }
    let(:issuer) { 'https://accounts.google.com' }
    let(:configs) { { 'google' => { 'enabled' => true, 'client_id' => 'cid', 'client_secret' => 'secret' } } }
    let(:claims) { { 'email' => 'Jane@Example.com', 'email_verified' => true } }

    before do
      Rails.cache.clear
      EncryptedConfig.create!(account:, key: EncryptedConfig::OIDC_CONFIGS_KEY, value: configs)
      stub_request(:get, "#{issuer}/.well-known/openid-configuration").to_return(
        headers: { 'Content-Type' => 'application/json' },
        body: { issuer:, authorization_endpoint: "#{issuer}/auth", token_endpoint: "#{issuer}/token",
                jwks_uri: "#{issuer}/jwks" }.to_json
      )
      stub_request(:get, "#{issuer}/jwks").to_return(body: { keys: [jwk.export] }.to_json)
    end

    def start_login(provider = 'google')
      get "/sso/oidc/#{provider}"
      expect(response).to have_http_status(:redirect)
      Rack::Utils.parse_query(URI.parse(response.location).query)
    end

    def id_token(nonce, overrides = {}, signing_key: key, kid: 'k1')
      payload = { iss: issuer, aud: 'cid', sub: '123', iat: Time.now.to_i, exp: 5.minutes.from_now.to_i, nonce: }
      JWT.encode(payload.merge(claims).merge(overrides), signing_key, 'RS256', { kid: })
    end

    def stub_token(token)
      stub_request(:post, "#{issuer}/token").to_return(body: { id_token: token, access_token: 'a' }.to_json)
    end

    it 'shows the provider button and signs in with a valid id_token' do
      get '/sign_in'
      expect(response.body).to include('Sign in with Google')

      query = start_login
      expect(query).to include('client_id' => 'cid', 'code_challenge_method' => 'S256',
                               'scope' => 'openid email profile')
      stub_token(id_token(query['nonce']))

      get "/sso/oidc/google/callback?code=abc&state=#{query['state']}"
      expect(response).to redirect_to('/')
      expect(signed_in?).to be(true)
      expect(WebMock).to have_requested(:post, "#{issuer}/token").with(body: hash_including('code_verifier'))
    end

    it 'rejects a state mismatch' do
      query = start_login
      stub_token(id_token(query['nonce']))
      get '/sso/oidc/google/callback?code=abc&state=forged'
      expect(response.location).to include('/sign_in')
      expect(signed_in?).to be(false)
    end

    it 'rejects a nonce mismatch' do
      query = start_login
      stub_token(id_token('other-nonce'))
      get "/sso/oidc/google/callback?code=abc&state=#{query['state']}"
      expect(signed_in?).to be(false)
    end

    it 'rejects an unverified email' do
      query = start_login
      stub_token(id_token(query['nonce'], { 'email_verified' => false }))
      get "/sso/oidc/google/callback?code=abc&state=#{query['state']}"
      expect(signed_in?).to be(false)
    end

    it 'rejects a token for another client' do
      query = start_login
      stub_token(id_token(query['nonce'], { aud: 'someone-else' }))
      get "/sso/oidc/google/callback?code=abc&state=#{query['state']}"
      expect(signed_in?).to be(false)
    end

    it 'rejects a token signed by an unknown key' do
      query = start_login
      stub_token(id_token(query['nonce'], {}, signing_key: OpenSSL::PKey::RSA.generate(2048), kid: 'k2'))
      get "/sso/oidc/google/callback?code=abc&state=#{query['state']}"
      expect(signed_in?).to be(false)
    end

    it 'rejects an email with no user' do
      query = start_login
      stub_token(id_token(query['nonce'], { 'email' => 'stranger@example.com' }))
      get "/sso/oidc/google/callback?code=abc&state=#{query['state']}"
      expect(signed_in?).to be(false)
    end

    context 'with Microsoft' do
      let(:configs) do
        { 'microsoft' => { 'enabled' => true, 'client_id' => 'cid', 'client_secret' => 's', 'tenant' => tenant } }
      end

      context 'with a shared tenant' do
        let(:tenant) { 'common' }

        it 'is not offered' do
          expect(OidcSso.enabled_providers(account)).to eq([])
          get '/sso/oidc/microsoft'
          expect(response.location).to include('/sign_in')
        end
      end

      context 'with a tenant ID' do
        let(:tenant) { 'contoso.onmicrosoft.com' }
        let(:issuer) { 'https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0' }
        let(:claims) { { 'preferred_username' => 'jane@example.com' } }

        it 'signs in using preferred_username' do
          query = start_login('microsoft')
          stub_token(id_token(query['nonce']))
          get "/sso/oidc/microsoft/callback?code=abc&state=#{query['state']}"
          expect(signed_in?).to be(true)
        end
      end
    end
  end

  describe 'magic link' do
    before { AccountConfig.create!(account:, key: AccountConfig::MAGIC_LINK_LOGIN_KEY, value: true) }

    it 'emails a link for known users and answers the same for unknown ones' do
      original_adapter = ActiveJob::Base.queue_adapter
      ActiveJob::Base.queue_adapter = :test
      get '/sign_in'
      expect(response.body).to include('Email me a sign-in link')

      expect { post '/sign_in/link', params: { email: 'jane@example.com' } }
        .to have_enqueued_mail(UserMailer, :magic_link_email)
      expect(response).to redirect_to('/sign_in')

      expect { post '/sign_in/link', params: { email: 'nobody@example.com' } }
        .not_to have_enqueued_mail(UserMailer, :magic_link_email)
      expect(response).to redirect_to('/sign_in')
    ensure
      ActiveJob::Base.queue_adapter = original_adapter
    end

    it 'renders the email with a working link' do
      mail = UserMailer.magic_link_email(user, MagicLink.generate(user))
      expect(mail.body.encoded).to include('/sign_in/link/open?token=')
    end

    it 'signs in once, on POST only' do
      token = MagicLink.generate(user)

      get '/sign_in/link/open', params: { token: }
      expect(response).to have_http_status(:ok)
      expect(response.body).to include('jane@example.com')
      expect(signed_in?).to be(false)

      post '/sign_in/link/open', params: { token: }
      expect(response).to redirect_to('/')
      expect(signed_in?).to be(true)

      delete '/sign_out'
      post '/sign_in/link/open', params: { token: }
      expect(response.location).to include('/sign_in')
      expect(signed_in?).to be(false)
    end

    it 'rejects tampered and expired tokens' do
      token = MagicLink.generate(user)
      post '/sign_in/link/open', params: { token: "#{token}x" }
      expect(signed_in?).to be(false)

      travel 16.minutes do
        post '/sign_in/link/open', params: { token: }
        expect(signed_in?).to be(false)
      end
    end

    it 'requires the two-factor code when enabled' do
      user.update!(otp_required_for_login: true, otp_secret: User.generate_otp_secret)
      token = MagicLink.generate(user)

      post '/sign_in/link/open', params: { token:, otp_attempt: '000000' }
      expect(response).to have_http_status(:unprocessable_content)
      expect(signed_in?).to be(false)

      post '/sign_in/link/open', params: { token:, otp_attempt: user.reload.current_otp }
      expect(signed_in?).to be(true)
    end

    it 'is disabled when SSO is forced' do
      EncryptedConfig.create!(account:, key: EncryptedConfig::OIDC_CONFIGS_KEY,
                              value: { 'google' => { 'enabled' => true, 'client_id' => 'c', 'client_secret' => 's' } })
      AccountConfig.create!(account:, key: AccountConfig::FORCE_SSO_AUTH_KEY, value: true)

      post '/sign_in/link/open', params: { token: MagicLink.generate(user) }
      expect(signed_in?).to be(false)

      post '/sign_in', params: { user: { email: 'jane@example.com', password: 'strong_password' } }
      expect(signed_in?).to be(false)
    end
  end

  describe 'settings page' do
    before do
      sign_in user
      stub_request(:get, 'https://acme.okta.com/.well-known/openid-configuration').to_return(
        body: { issuer: 'https://acme.okta.com', authorization_endpoint: 'https://acme.okta.com/a',
                token_endpoint: 'https://acme.okta.com/t', jwks_uri: 'https://acme.okta.com/k' }.to_json
      )
    end

    it 'renders every section' do
      get '/settings/sso'
      expect(response).to have_http_status(:ok)
      expect(response.body).to include('Email sign-in links', 'Google', 'Microsoft', 'Okta', 'SAML',
                                       '/sso/oidc/okta/callback')
    end

    it 'saves providers, keeps a blank secret, and validates input' do
      post '/settings/sso/oidc', params: { oidc: { okta: { enabled: '1', domain: 'acme.okta.com',
                                                           client_id: 'id', client_secret: 'sec' } } }
      expect(response).to redirect_to('/settings/sso')

      post '/settings/sso/oidc', params: { oidc: { okta: { enabled: '1', domain: 'acme.okta.com',
                                                           client_id: 'id2', client_secret: '' } } }
      follow_redirect!
      expect(OidcSso.provider_config(account, 'okta')).to include('client_id' => 'id2', 'client_secret' => 'sec')
      expect(OidcSso.enabled_providers(account)).to eq(['okta'])

      post '/settings/sso/oidc', params: { oidc: { microsoft: { enabled: '1', tenant: 'common',
                                                                client_id: 'x', client_secret: 'y' } } }
      expect(response).to have_http_status(:unprocessable_content)
      expect(response.body).to include('not a shared tenant')
    end

    it 'toggles magic links and forced SSO' do
      post '/settings/sso/magic_link', params: { magic_link_enabled: '1', force_sso: '1' }
      expect(MagicLink.enabled?).to be(true)
      expect(AccountConfig.find_by(account:, key: AccountConfig::FORCE_SSO_AUTH_KEY).value).to be(true)
    end
  end
end
