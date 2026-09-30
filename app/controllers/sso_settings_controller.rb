# frozen_string_literal: true

class SsoSettingsController < ApplicationController
  before_action :load_encrypted_config
  authorize_resource :encrypted_config, only: :index
  authorize_resource :encrypted_config, parent: false, only: %i[create update_oidc update_magic_link]

  def index
    load_page_state
  end

  def create
    value = saml_value
    @encrypted_config.value = value

    if value['sso_url'].blank? && value['certificate'].blank?
      @encrypted_config.destroy! if @encrypted_config.persisted?
      redirect_to settings_sso_index_path, notice: I18n.t('sso_settings_have_been_updated')
      return
    end

    unless Saml.valid_sso_url?(value['sso_url']) && Saml.valid_certificate?(value['certificate'])
      load_page_state
      flash.now[:alert] = 'Enter a valid SSO Service URL and an X.509 certificate.'
      render :index, status: :unprocessable_content
      return
    end

    @encrypted_config.save!
    redirect_to settings_sso_index_path, notice: I18n.t('sso_settings_have_been_updated')
  end

  def update_oidc
    record = EncryptedConfig.find_or_initialize_by(account: current_account, key: EncryptedConfig::OIDC_CONFIGS_KEY)
    current = record.value.is_a?(Hash) ? record.value : {}
    value = oidc_value(current)

    errors = oidc_errors(value)
    if errors.any?
      load_page_state(oidc_configs: value)
      flash.now[:alert] = errors.join(' ')
      render :index, status: :unprocessable_content
      return
    end

    record.value = value
    record.save!
    redirect_to settings_sso_index_path, notice: I18n.t('sso_settings_have_been_updated')
  end

  def update_magic_link
    set_account_flag(AccountConfig::MAGIC_LINK_LOGIN_KEY, params[:magic_link_enabled] == '1')
    set_account_flag(AccountConfig::FORCE_SSO_AUTH_KEY, params[:force_sso] == '1')
    redirect_to settings_sso_index_path, notice: I18n.t('sso_settings_have_been_updated')
  end

  private

  def load_encrypted_config
    @encrypted_config =
      EncryptedConfig.find_or_initialize_by(account: current_account, key: EncryptedConfig::SAML_CONFIGS_KEY)
  end

  def load_page_state(oidc_configs: nil)
    @force_sso = account_flag?(AccountConfig::FORCE_SSO_AUTH_KEY)
    @magic_link_enabled = account_flag?(AccountConfig::MAGIC_LINK_LOGIN_KEY)
    @oidc_configs = oidc_configs || OidcSso.configs_for(current_account)
  end

  def saml_value
    submitted = params.require(:encrypted_config).permit(value: %i[sso_url certificate]).fetch(:value, {})
    current = @encrypted_config.value.is_a?(Hash) ? @encrypted_config.value : {}
    certificate = Saml.normalize_certificate(submitted[:certificate])
    certificate = current['certificate'].to_s if certificate.blank?

    {
      'sso_url' => submitted[:sso_url].to_s.strip,
      'certificate' => certificate
    }
  end

  # Blank client secrets keep the stored value so the form never has to echo secrets back.
  def oidc_value(current)
    submitted = params.fetch(:oidc, {}).permit(
      OidcSso::PROVIDERS.to_h { |provider, meta| [provider, meta[:fields] + ['enabled']] }
    )

    OidcSso::PROVIDERS.to_h do |provider, meta|
      input = submitted.fetch(provider, {})
      stored = current[provider] || {}
      config = meta[:fields].index_with { |field| input[field].to_s.strip }
      config['client_secret'] = stored['client_secret'].to_s if config['client_secret'].blank?
      config['enabled'] = input['enabled'] == '1'
      [provider, config]
    end
  end

  def oidc_errors(value)
    value.filter_map do |provider, config|
      next unless config['enabled']

      name = OidcSso.display_name(provider)
      missing = OidcSso::PROVIDERS[provider][:fields].select { |field| config[field].blank? }
      next "#{name}: #{missing.map(&:humanize).join(', ')} required." if missing.any?

      issuer = OidcSso.issuer(provider, config)
      next "#{name}: use your directory (tenant) ID, not a shared tenant." if issuer.blank? && provider == 'microsoft'
      next "#{name}: enter a valid domain." if issuer.blank?

      begin
        OidcSso.discovery(issuer)
        nil
      rescue OidcSso::Error, SocketError, Timeout::Error, SystemCallError, OpenSSL::SSL::SSLError => e
        "#{name}: could not reach #{issuer} (#{e.message})."
      end
    end
  end

  def account_flag?(key)
    AccountConfig.find_by(account: current_account, key:)&.value == true
  end

  def set_account_flag(key, enabled)
    config = AccountConfig.find_or_initialize_by(account: current_account, key:)
    if enabled
      config.update!(value: true)
    elsif config.persisted?
      config.destroy!
    end
  end
end
